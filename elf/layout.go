package elf

import "fmt"

// Piece records where one input section's data lands within a MergedSection.
type Piece struct {
	Obj    *Object
	Sec    *ObjectSection
	Offset uint64 // byte offset within MergedSection.Data
}

type MergedSection struct {
    Name     string
    Flags    SectionFlags
    RawType  uint32
    RawFlags uint64
    Align    uint64
    EntSize  uint64  // sh_entsize; 0 = not fixed-size entries

    Pieces []Piece
    Data   []byte
    Size   uint64

    VAddr      uint64
    FileOffset uint64
}

// Layout holds the complete set of merged output sections.
type Layout struct {
	Sections  []*MergedSection
	secByName map[string]*MergedSection
}

// SectionByName looks up a merged output section by name.
func (l *Layout) SectionByName(name string) (*MergedSection, bool) {
	s, ok := l.secByName[name]
	return s, ok
}

const layoutPageSize = uint64(0x1000) // 4 KiB PT_LOAD alignment

// MergeSections groups input sections from all objects by name and
// concatenates their data, respecting per-section alignment requirements.
func MergeSections(objects []*Object) (*Layout, error) {
	var order []string
	byKey := make(map[string]*MergedSection)

	for _, obj := range objects {
		for _, sec := range obj.Sections {
			if sec == nil || sec.Index == 0 || sec.Name == "" || sec.Skip {
				continue
			}
			ms, exists := byKey[sec.Name]
			if !exists {
				ms = &MergedSection{
					Name:     sec.Name,
					Flags:    sec.Flags,
					RawType:  sec.RawType,
					RawFlags: sec.RawFlags,
					Align:    1,
				}
				byKey[sec.Name] = ms
				order = append(order, sec.Name)
			}
			if sec.Align > ms.Align {
				ms.Align = sec.Align
			}

			var pieceOffset uint64
			if sec.Flags&SecBSS == 0 {
				cur := uint64(len(ms.Data))
				aligned := alignUp(cur, sec.Align)
				for uint64(len(ms.Data)) < aligned {
					ms.Data = append(ms.Data, 0)
				}
				pieceOffset = aligned
				ms.Data = append(ms.Data, sec.Data...)
			} else {
				aligned := alignUp(ms.Size, sec.Align)
				pieceOffset = aligned
				ms.Size = aligned + sec.Size
			}
			ms.Pieces = append(ms.Pieces, Piece{Obj: obj, Sec: sec, Offset: pieceOffset})
		}
	}

	sections := make([]*MergedSection, 0, len(order))
	for _, k := range order {
		ms := byKey[k]
		if ms.Flags&SecBSS == 0 {
			ms.Size = uint64(len(ms.Data))
		}
		sections = append(sections, ms)
	}
	return &Layout{Sections: sections, secByName: byKey}, nil
}

// AssignLayout assigns VAddr and FileOffset to every merged section.
// baseVA sets the virtual-address base; 0 selects 0x400000 for OutputExec,
// 0 for all other output types.
// Sections are grouped into three PT_LOAD segments: RX, RO, RW.
// Non-allocatable sections are placed at end-of-file.
func AssignLayout(outputType OutputType, layout *Layout, baseVA uint64) error {
	if baseVA == 0 && outputType == OutputExec {
		baseVA = 0x400000
	}

	fileOff := layoutPageSize
	vaddr := baseVA + fileOff

	var exSecs, roSecs, rwSecs, nonAlloc []*MergedSection
	for _, ms := range layout.Sections {
		if ms.Flags&SecAlloc == 0 {
			nonAlloc = append(nonAlloc, ms)
		} else if ms.Flags&SecWrite != 0 {
			rwSecs = append(rwSecs, ms)
		} else if ms.Flags&SecExec != 0 {
			exSecs = append(exSecs, ms)
		} else {
			roSecs = append(roSecs, ms)
		}
	}

	assign := func(secs []*MergedSection, newSegment bool) {
		if len(secs) == 0 {
			return
		}
		if newSegment {
			fileOff = alignUp(fileOff, layoutPageSize)
			vaddr = alignUp(vaddr, layoutPageSize)
		}
		for _, ms := range secs {
			fileOff = alignUp(fileOff, ms.Align)
			vaddr = alignUp(vaddr, ms.Align)
			ms.FileOffset = fileOff
			ms.VAddr = vaddr
			if ms.Flags&SecBSS == 0 {
				fileOff += ms.Size
			}
			vaddr += ms.Size
		}
	}

	assign(exSecs, false)
	assign(roSecs, len(exSecs) > 0)
	assign(rwSecs, len(exSecs)+len(roSecs) > 0)

	for _, ms := range nonAlloc {
		fileOff = alignUp(fileOff, ms.Align)
		ms.FileOffset = fileOff
		ms.VAddr = 0
		if ms.Flags&SecBSS == 0 {
			fileOff += ms.Size
		}
	}
	return nil
}

// ResolveSymbolAddresses fills in VAddr for every defined symbol using the
// section addresses assigned by AssignLayout.
func ResolveSymbolAddresses(symtab *SymbolTable, layout *Layout) error {
	// --- MAGIC LINKER SYMBOLS ---
	// Intercept _GLOBAL_OFFSET_TABLE_ and point it to the GOT base.
	if gotSym := symtab.Lookup("_GLOBAL_OFFSET_TABLE_"); gotSym != nil {
		gotSym.Kind = kindDefined // Mask as defined
		
		if gotplt, ok := layout.SectionByName(".got.plt"); ok {
			gotSym.VAddr = gotplt.VAddr
		} else if got, ok := layout.SectionByName(".got"); ok {
			gotSym.VAddr = got.VAddr
		}
	}
	// ----------------------------

	for _, sym := range symtab.All() {
		if !sym.IsDefined() || sym.RawSym == nil {
			continue
		}
		raw := sym.RawSym
		switch raw.SectionName {
		case "*ABS*":
			sym.VAddr = raw.Value
			continue
		case "":
			continue
		}
		
		ms, ok := layout.SectionByName(raw.SectionName)
		if !ok {
			continue
		}
		
		for _, pc := range ms.Pieces {
			if pc.Obj == sym.Object && pc.Sec != nil && pc.Sec.Index == raw.SectionIdx {
				sym.VAddr = ms.VAddr + pc.Offset + raw.Value
				break
			}
		}
	}
	return nil
}