package pe

import "fmt"

// Piece records where one input section's data lands within a MergedSection.
type Piece struct {
	Obj    *Object
	Sec    *ObjectSection
	Offset uint64
}

// MergedSection is the result of combining all same-named input sections.
type MergedSection struct {
	Name     string
	Flags    SectionFlags
	RawType  uint32
	RawFlags uint64
	Align    uint64

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

const layoutPageSize = uint64(0x1000)

// MergeSections groups input sections from all objects by name and concatenates
// their data, respecting per-section alignment requirements.
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

// AppendAllocSection places a newly generated allocatable section contiguously
// after the highest allocated VAddr, using the same page-rounding rule as
// AssignLayout. It is the single placement primitive for sections whose size
// is only known after AssignLayout has run (e.g. .reloc, sized post-relocation).
// File offset is left to the writer, which packs all sections in one pass.
func (l *Layout) AppendAllocSection(name string, data []byte, flags SectionFlags, align uint64) *MergedSection {
	var maxEnd uint64
	for _, ms := range l.Sections {
		if ms.Flags&SecAlloc == 0 {
			continue
		}
		if end := ms.VAddr + alignUp(ms.Size, layoutPageSize); end > maxEnd {
			maxEnd = end
		}
	}
	sec := &MergedSection{
		Name:  name,
		Flags: flags | SecAlloc,
		Data:  data,
		Size:  uint64(len(data)),
		Align: align,
		VAddr: alignUp(maxEnd, layoutPageSize),
	}
	l.Sections = append(l.Sections, sec)
	l.secByName[name] = sec
	return sec
}

// AssignLayout assigns VAddr and FileOffset to every merged section.
// Sections are grouped into RX, RO, and RW PT_LOAD segments; non-allocatable
// sections (debug info etc.) are placed at end-of-file.
//
// Virtual addresses tile contiguously from the first section up to
// SizeOfImage with no gaps: the NT loader validates, during image-section
// creation, that each section's VirtualAddress equals the previous section's
// VirtualAddress plus its page-rounded VirtualSize. A hole (an RVA range
// covered by no section header) is rejected with ERROR_BAD_EXE_FORMAT (Win32
// 193) before any code runs. We therefore advance vaddr by the page-rounded
// section size, not the raw size.
//
// File offsets are repacked densely by the writer at peFileAlign; ms.FileOffset
// set here is advisory and never read by the writer.
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
		}
		for _, ms := range secs {
			vaddr = alignUp(vaddr, layoutPageSize)
			fileOff = alignUp(fileOff, ms.Align)
			ms.FileOffset = fileOff
			ms.VAddr = vaddr
			if ms.Flags&SecBSS == 0 {
				fileOff += ms.Size
			}
			vaddr += alignUp(ms.Size, layoutPageSize)
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
			return fmt.Errorf("symbol %q references unknown output section %q", sym.Name, raw.SectionName)
		}
		var pieceOff uint64
		found := false
		for _, p := range ms.Pieces {
			if p.Obj == sym.Object && p.Sec.Name == raw.SectionName {
				pieceOff = p.Offset
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("symbol %q: piece not found in output section %q", sym.Name, raw.SectionName)
		}
		sym.VAddr = ms.VAddr + pieceOff + raw.Value
	}
	return nil
}

func alignUp(v, align uint64) uint64 {
	if align <= 1 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}