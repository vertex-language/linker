package macho

import "fmt"

// Patcher applies a single relocation to a byte slice.
type Patcher interface {
	Apply(data []byte, off int, relType uint32, P, S uint64, A int64) error
}

// PatchAll applies every relocation from every input object to the merged
// output section data. Must be called after AssignLayout and ResolveSymbolAddresses.
func PatchAll(layout *Layout, symtab *SymbolTable, objects []*Object, p Patcher) error {
	for _, obj := range objects {
		for _, rel := range obj.Relocs {
			if err := applyOne(layout, symtab, obj, rel, p); err != nil {
				return fmt.Errorf("%s: %w", obj.Name, err)
			}
		}
	}
	return nil
}

func applyOne(layout *Layout, symtab *SymbolTable, obj *Object, rel *ObjectReloc, p Patcher) error {
	if rel.TargetSectionIdx >= len(obj.Sections) {
		return fmt.Errorf("reloc target section index %d out of range", rel.TargetSectionIdx)
	}
	inputSec := obj.Sections[rel.TargetSectionIdx]
	if inputSec == nil || inputSec.Skip {
		return nil
	}

	outSec, ok := layout.SectionByName(inputSec.Name)
	if !ok {
		return nil // GC'd or linker-internal
	}

	var pieceOff uint64
	found := false
	for _, piece := range outSec.Pieces {
		if piece.Obj == obj && piece.Sec == inputSec {
			pieceOff = piece.Offset
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("reloc: piece for %q not found in output section %q", inputSec.Name, outSec.Name)
	}

	patchOff := int(pieceOff + rel.Offset)
	if patchOff >= len(outSec.Data) {
		return fmt.Errorf("reloc patch offset 0x%x out of bounds in %q (size=%d)",
			patchOff, outSec.Name, len(outSec.Data))
	}

	P := outSec.VAddr + pieceOff + rel.Offset
	S, err := resolveRelocSym(rel, obj, symtab)
	if err != nil {
		return err
	}
	return p.Apply(outSec.Data, patchOff, rel.Type, P, uint64(S), rel.Addend)
}

func resolveRelocSym(rel *ObjectReloc, obj *Object, symtab *SymbolTable) (int64, error) {
	if rel.SymIdx == 0 {
		return 0, nil
	}
	if int(rel.SymIdx) >= len(obj.Symbols) {
		return 0, fmt.Errorf("reloc symbol index %d out of range", rel.SymIdx)
	}
	raw := obj.Symbols[rel.SymIdx]
	if raw == nil || raw.Name == "" {
		return 0, nil // section-relative
	}
	sym := symtab.Lookup(raw.Name)
	if sym == nil {
		if raw.Binding == BindWeak {
			return 0, nil
		}
		return 0, fmt.Errorf("undefined symbol %q", raw.Name)
	}
	switch sym.Kind {
	case kindDefined, kindCommon, kindShared:
		return int64(sym.VAddr), nil
	case kindUndefined:
		if sym.Weak {
			return 0, nil
		}
		return 0, fmt.Errorf("undefined symbol %q", raw.Name)
	}
	return 0, fmt.Errorf("symbol %q in unexpected state", raw.Name)
}