package pe

import "encoding/binary"

const (
	pltHeaderSize = 16
	pltEntrySize  = 16
	gotEntrySize  = 8
	gotReserved   = 3 // standard reserved .got.plt header slots
)

// PLTEntry pairs a shared symbol with its 0-based stub index (PLT0 not counted).
type PLTEntry struct {
	Name string
	Sym  *TableSymbol
	Idx  int
}

// PLTPatcher writes arch-specific PLT thunks. PE imports resolve through the
// IAT in .got.plt and the import directory — there is no ELF-style .rela.plt.
type PLTPatcher interface {
	PatchPLT(plt, gotPLT []byte, pltBase, gotBase uint64, syms []PLTEntry)
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

// InjectPLTSections appends placeholder .plt and .got.plt sections so they
// receive virtual addresses during AssignLayout.
//
// No .rela.plt is injected. PE resolves imports through the IAT and import
// directory rather than ELF RELA entries; an allocatable section that
// AssignLayout addresses but the emitter never writes would leave an uncovered
// RVA range, which the NT image loader rejects with ERROR_BAD_EXE_FORMAT.
func InjectPLTSections(layout *Layout, syms []PLTEntry) {
	n := len(syms)
	plt := &MergedSection{
		Name:  ".plt",
		Flags: SecAlloc | SecExec,
		Data:  make([]byte, pltHeaderSize+n*pltEntrySize),
		Size:  uint64(pltHeaderSize + n*pltEntrySize),
		Align: 16,
	}
	gotPLT := &MergedSection{
		Name:  ".got.plt",
		Flags: SecAlloc | SecWrite,
		Data:  make([]byte, (gotReserved+n)*gotEntrySize),
		Size:  uint64((gotReserved + n) * gotEntrySize),
		Align: 8,
	}
	layout.Sections = append(layout.Sections, plt, gotPLT)
	layout.secByName[".plt"] = plt
	layout.secByName[".got.plt"] = gotPLT
}

// PatchPLT fills the PLT thunks and assigns each PLT symbol's VAddr to its stub.
func PatchPLT(pp PLTPatcher, layout *Layout, syms []PLTEntry) error {
	pltSec, ok1 := layout.SectionByName(".plt")
	gotSec, ok2 := layout.SectionByName(".got.plt")
	if !ok1 || !ok2 {
		return nil
	}
	pp.PatchPLT(pltSec.Data, gotSec.Data, pltSec.VAddr, gotSec.VAddr, syms)
	return nil
}

// PutI32LE writes a signed little-endian 32-bit integer into b[0:4].
func PutI32LE(b []byte, v int32) { binary.LittleEndian.PutUint32(b, uint32(v)) }