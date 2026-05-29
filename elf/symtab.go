package elf

import "fmt"

// symKind is the resolution precedence of a global symbol entry.
type symKind int

const (
	kindUndefined symKind = iota
	kindLazy                     // definition available in an archive (not yet extracted)
	kindShared                   // defined in a dynamic library
	kindCommon                   // tentative C common block (SHN_COMMON)
	kindDefined                  // hard definition in a relocatable object
)

// TableSymbol is the linker's global view of one symbol.
type TableSymbol struct {
	Name string
	Kind symKind
	Weak bool

	// kindDefined / kindCommon
	Object *Object
	RawSym *ObjectSymbol

	// kindLazy
	Archive *Archive
	Member  *ArchiveMember

	// kindShared
	Lib    *SharedLib
	Export *SharedExport

	// Filled by ResolveSymbolAddresses after layout.
	VAddr uint64
}

func (s *TableSymbol) IsDefined() bool   { return s.Kind == kindDefined || s.Kind == kindCommon }
func (s *TableSymbol) IsUndefined() bool { return s.Kind == kindUndefined }
func (s *TableSymbol) IsShared() bool    { return s.Kind == kindShared }

// SymbolTable is the linker's global symbol table.
type SymbolTable struct {
	entries   map[string]*TableSymbol
	objUndefs map[string]bool // undefined refs from .o files — drives archive extraction
}

// NewSymbolTable returns an empty SymbolTable.
func NewSymbolTable() *SymbolTable {
	return &SymbolTable{
		entries:   make(map[string]*TableSymbol),
		objUndefs: make(map[string]bool),
	}
}

// Lookup returns the TableSymbol for name, or nil.
func (t *SymbolTable) Lookup(name string) *TableSymbol { return t.entries[name] }

// All returns every symbol in the table (order unspecified).
func (t *SymbolTable) All() []*TableSymbol {
	out := make([]*TableSymbol, 0, len(t.entries))
	for _, s := range t.entries {
		out = append(out, s)
	}
	return out
}

// Ingest processes all inputs and performs symbol resolution.
// Follows classical Unix left-to-right command-line semantics:
//
//  1. Object files are processed first and define the initial symbol set.
//  2. Shared libraries contribute symbols only if not already defined.
//  3. Archives are iterated repeatedly until no new members are extracted.
//  4. Unresolved strong undefs from object files produce an error.
func (t *SymbolTable) Ingest(objects []*Object, archives []*Archive, shared []*SharedLib) error {
	for _, obj := range objects {
		if err := t.ingestObject(obj); err != nil {
			return err
		}
	}
	for _, lib := range shared {
		t.ingestShared(lib)
	}
	for {
		extracted := false
		for _, ar := range archives {
			n, err := t.extractFromArchive(ar)
			if err != nil {
				return err
			}
			if n > 0 {
				extracted = true
			}
		}
		if !extracted {
			break
		}
	}
	for name, sym := range t.entries {
		if sym.Kind == kindUndefined && !sym.Weak && t.objUndefs[name] {
			return fmt.Errorf("undefined reference to %q", name)
		}
	}
	return nil
}

func (t *SymbolTable) ingestObject(obj *Object) error {
	for _, raw := range obj.Symbols {
		if raw == nil || raw.Name == "" || raw.Binding == BindLocal {
			continue
		}
		switch raw.SectionIdx {
		case SymSecUndef:
			t.objUndefs[raw.Name] = true
			t.ensureUndefined(raw.Name, raw.Binding == BindWeak)
		case SymSecCommon:
			if err := t.resolveCommon(raw.Name, raw, obj); err != nil {
				return err
			}
		default:
			if err := t.resolveDefinition(raw.Name, raw, obj); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *SymbolTable) ingestShared(lib *SharedLib) {
	for name, exp := range lib.Exports {
		if exp.Binding != BindGlobal && exp.Binding != BindWeak {
			continue
		}
		existing := t.entries[name]
		if existing == nil || existing.Kind == kindUndefined || existing.Kind == kindLazy {
			t.entries[name] = &TableSymbol{
				Name:   name,
				Kind:   kindShared,
				Lib:    lib,
				Export: exp,
				Weak:   exp.Binding == BindWeak,
			}
		}
	}
}

func (t *SymbolTable) extractFromArchive(ar *Archive) (int, error) {
	extracted := 0
	for name := range t.objUndefs {
		sym := t.entries[name]
		if sym == nil || sym.Kind != kindUndefined || sym.Weak {
			continue
		}
		m := ar.MemberForSymbol(name)
		if m == nil {
			continue
		}
		obj, err := m.Object()
		if err != nil {
			return extracted, fmt.Errorf("extracting %q from %s: %w", name, ar.Name, err)
		}
		if err := t.ingestObject(obj); err != nil {
			return extracted, err
		}
		extracted++
	}
	return extracted, nil
}

func (t *SymbolTable) ensureUndefined(name string, weak bool) {
	if t.entries[name] == nil {
		t.entries[name] = &TableSymbol{Name: name, Kind: kindUndefined, Weak: weak}
	}
}

func (t *SymbolTable) resolveDefinition(name string, raw *ObjectSymbol, obj *Object) error {
	incoming := &TableSymbol{
		Name:   name,
		Kind:   kindDefined,
		Object: obj,
		RawSym: raw,
		Weak:   raw.Binding == BindWeak,
	}
	existing := t.entries[name]
	if existing == nil {
		t.entries[name] = incoming
		return nil
	}
	switch existing.Kind {
	case kindUndefined, kindLazy, kindShared, kindCommon:
		t.entries[name] = incoming
	case kindDefined:
		switch {
		case existing.Weak && !incoming.Weak:
			t.entries[name] = incoming
		case !existing.Weak && incoming.Weak:
			// keep existing strong; drop incoming weak
		case existing.Weak && incoming.Weak:
			// first weak wins (matches ld / lld behaviour)
		default:
			return fmt.Errorf("duplicate definition of %q (in %s and %s)",
				name, existing.Object.Name, obj.Name)
		}
	}
	return nil
}

func (t *SymbolTable) resolveCommon(name string, raw *ObjectSymbol, obj *Object) error {
	incoming := &TableSymbol{Name: name, Kind: kindCommon, Object: obj, RawSym: raw}
	existing := t.entries[name]
	if existing == nil {
		t.entries[name] = incoming
		return nil
	}
	switch existing.Kind {
	case kindUndefined, kindLazy, kindShared:
		t.entries[name] = incoming
	case kindCommon:
		if raw.Value > existing.RawSym.Value {
			t.entries[name] = incoming
		}
	case kindDefined:
		// hard definition beats common; drop incoming
	}
	return nil
}