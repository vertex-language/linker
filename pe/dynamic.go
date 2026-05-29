package pe

import "encoding/binary"

const (
	pltHeaderSize = 16
	pltEntrySize  = 16
	gotEntrySize  = 8
	relaEntSize   = 24
)

// PLTEntry pairs a shared symbol with its 0-based stub index (PLT0 not counted).
type PLTEntry struct {
	Name string
	Sym  *TableSymbol
	Idx  int
}

// PLTPatcher writes arch+format-specific PLT stubs and dynamic reloc entries.
type PLTPatcher interface {
	PatchPLT(plt, gotPLT, relaPLT []byte, pltBase, gotBase uint64, syms []PLTEntry)
}

// CollectPLTSymbols returns every kindShared symbol actually referenced by at
// least one object relocation, in stable first-seen order.
func CollectPLTSymbols(symtab *SymbolTable, objects []*Object) []PLTEntry {
	referenced := make(map[string]bool)
	for _, obj := range objects {
		for _, rel := range obj.Relocs {
			if int(rel.SymIdx) < len(obj.Symbols) && obj.Symbols[rel.SymIdx] != nil {
				if name := obj.Symbols[rel.SymIdx].Name; name != "" {
					referenced[name] = true
				}
			}
		}
	}

	var out []PLTEntry
	seen := make(map[string]bool)
	for _, obj := range objects {
		for _, raw := range obj.Symbols {
			if raw == nil || raw.Name == "" || seen[raw.Name] || !referenced[raw.Name] {
				continue
			}
			sym := symtab.Lookup(raw.Name)
			if sym == nil || !sym.IsShared() {
				continue
			}
			seen[raw.Name] = true
			out = append(out, PLTEntry{Name: raw.Name, Sym: sym, Idx: len(out)})
		}
	}
	return out
}

// InjectPLTSections appends placeholder .plt, .got.plt, and .rela.plt sections
// so they receive virtual addresses during AssignLayout.
func InjectPLTSections(layout *Layout, syms []PLTEntry) {
	n := len(syms)
	plt := &MergedSection{
		Name:     ".plt",
		Flags:    SecAlloc | SecExec,
		RawType:  1,
		RawFlags: 0x2 | 0x4,
		Data:     make([]byte, pltHeaderSize+n*pltEntrySize),
		Size:     uint64(pltHeaderSize + n*pltEntrySize),
		Align:    16,
	}
	gotPLT := &MergedSection{
		Name:     ".got.plt",
		Flags:    SecAlloc | SecWrite,
		RawType:  1,
		RawFlags: 0x2 | 0x1,
		Data:     make([]byte, (3+n)*gotEntrySize),
		Size:     uint64((3 + n) * gotEntrySize),
		Align:    8,
	}
	relaPLT := &MergedSection{
		Name:     ".rela.plt",
		Flags:    SecAlloc,
		RawType:  4,
		RawFlags: 0x2 | 0x40,
		Data:     make([]byte, n*relaEntSize),
		Size:     uint64(n * relaEntSize),
		Align:    8,
	}
	layout.Sections = append(layout.Sections, plt, gotPLT, relaPLT)
	layout.secByName[".plt"] = plt
	layout.secByName[".got.plt"] = gotPLT
	layout.secByName[".rela.plt"] = relaPLT
}

// PatchPLT fills PLT stubs, GOT.PLT slots, and JUMP_SLOT reloc entries, then
// assigns each PLT symbol's VAddr to its stub.
func PatchPLT(pp PLTPatcher, layout *Layout, syms []PLTEntry) error {
	pltSec, ok1 := layout.SectionByName(".plt")
	gotSec, ok2 := layout.SectionByName(".got.plt")
	relaSec, ok3 := layout.SectionByName(".rela.plt")
	if !ok1 || !ok2 || !ok3 {
		return nil
	}
	pp.PatchPLT(pltSec.Data, gotSec.Data, relaSec.Data, pltSec.VAddr, gotSec.VAddr, syms)
	return nil
}

// PutI32LE writes a signed little-endian 32-bit integer into b[0:4].
func PutI32LE(b []byte, v int32) { binary.LittleEndian.PutUint32(b, uint32(v)) }