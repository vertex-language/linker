// patch.go — RELA relocation application pass.
package elf

import "fmt"

// Patcher applies a single RELA relocation to in-memory section data.
//
// Parameters follow ELF spec conventions:
//   data    — the merged output section's byte slice (mutated in place)
//   off     — byte offset within data of the field to patch
//   relType — arch-specific relocation type (R_X86_64_*, R_AARCH64_*, …)
//   P       — virtual address of the relocation field
//   S       — virtual address of the referenced symbol
//   A       — explicit addend from the RELA entry
type Patcher interface {
	Apply(data []byte, off int, relType uint32, P, S uint64, A int64) error
}

// PatchAll iterates every relocation in every object and writes the computed
// value into the merged output section data.  It must be called after
// ResolveSymbolAddresses and PatchPLT so that all VAddrs are final.
func PatchAll(layout *Layout, symtab *SymbolTable, objects []*Object, p Patcher) error {
	for _, obj := range objects {
		for _, rel := range obj.Relocs {
			if err := applyReloc(layout, symtab, obj, rel, p); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyReloc(layout *Layout, symtab *SymbolTable, obj *Object, rel *ObjectReloc, p Patcher) error {
	// Validate the target section index.
	if rel.TargetSectionIdx <= 0 || rel.TargetSectionIdx >= len(obj.Sections) {
		return nil
	}
	targetSec := obj.Sections[rel.TargetSectionIdx]
	if targetSec == nil || targetSec.Skip {
		return nil
	}

	// Find the merged output section that absorbed this input section.
	ms, ok := layout.SectionByName(targetSec.Name)
	if !ok {
		return nil
	}
	if ms.Flags&SecBSS != 0 {
		return nil // BSS has no file bytes to patch.
	}

	// Locate the piece contributed by this specific object.
	var pieceOff uint64
	found := false
	for _, pc := range ms.Pieces {
		if pc.Obj == obj && pc.Sec == targetSec {
			pieceOff = pc.Offset
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	// P = virtual address of the relocation field.
	P := ms.VAddr + pieceOff + rel.Offset

	// S = virtual address of the referenced symbol.
	var S uint64
	if rel.SymIdx > 0 && int(rel.SymIdx) < len(obj.Symbols) {
		rawSym := obj.Symbols[rel.SymIdx]
		if rawSym != nil {
			switch {
			case rawSym.SectionIdx == SymSecAbs:
				// Absolute symbol: the value is the literal address.
				S = rawSym.Value

			case rawSym.Name != "":
				// Named symbol: check the global symbol table first (covers
				// STB_GLOBAL definitions and PLT stubs patched by PatchPLT).
				if ts := symtab.Lookup(rawSym.Name); ts != nil {
					S = ts.VAddr
				} else if rawSym.SectionIdx >= 0 && rawSym.SectionIdx < len(obj.Sections) {
					// Not in the global table — this is a STB_LOCAL named symbol
					// (e.g. a compiler-generated read-only data label like data0).
					// The global symtab skips locals during ingest, so we resolve
					// it the same way as an anonymous section symbol: walk the
					// merged section's piece list for this object.
					symSec := obj.Sections[rawSym.SectionIdx]
					if symSec != nil {
						if symMs, ok2 := layout.SectionByName(symSec.Name); ok2 {
							for _, pc := range symMs.Pieces {
								if pc.Obj == obj && pc.Sec == symSec {
									S = symMs.VAddr + pc.Offset + rawSym.Value
									break
								}
							}
						}
					}
				}

			case rawSym.SectionIdx >= 0 && rawSym.SectionIdx < len(obj.Sections):
				// Anonymous section symbol (STT_SECTION): resolve through the
				// merged section that contains this object's piece of that section.
				symSec := obj.Sections[rawSym.SectionIdx]
				if symSec != nil {
					if symMs, ok2 := layout.SectionByName(symSec.Name); ok2 {
						for _, pc := range symMs.Pieces {
							if pc.Obj == obj && pc.Sec == symSec {
								S = symMs.VAddr + pc.Offset + rawSym.Value
								break
							}
						}
					}
				}
			}
		}
	}

	dataOff := int(pieceOff + rel.Offset)
	if dataOff < 0 || dataOff > len(ms.Data) {
		return fmt.Errorf("reloc in %s section %s offset 0x%x: patch offset %d out of bounds (section %d bytes)",
			obj.Name, targetSec.Name, rel.Offset, dataOff, len(ms.Data))
	}

	if err := p.Apply(ms.Data, dataOff, rel.Type, P, S, rel.Addend); err != nil {
		return fmt.Errorf("reloc in %s section %s offset 0x%x: %w",
			obj.Name, targetSec.Name, rel.Offset, err)
	}
	return nil
}