package elf

// GC performs dead-section elimination by traversing the reachability graph
// starting from the entry point (for executables) or all exported symbols
// (for shared libraries). Unreachable SHF_ALLOC sections are removed from
// the layout before address assignment.
//
// GC is a no-op when entry is empty and outputType is not OutputShared.
func GC(layout *Layout, symtab *SymbolTable, objects []*Object, outputType OutputType, entry string) {
	var roots []string
	if outputType == OutputShared {
		for _, sym := range symtab.All() {
			if sym.IsDefined() && !sym.Weak && sym.RawSym != nil &&
				sym.RawSym.Binding == BindGlobal && sym.RawSym.SectionName != "" {
				roots = append(roots, sym.Name)
			}
		}
	} else if entry != "" {
		roots = []string{entry}
	}
	if len(roots) == 0 {
		return
	}

	type secKey struct {
		obj  *Object
		name string
	}
	secToMerged := make(map[secKey]*MergedSection)
	for _, ms := range layout.Sections {
		for _, p := range ms.Pieces {
			secToMerged[secKey{p.Obj, p.Sec.Name}] = ms
		}
	}

	reachable := make(map[*MergedSection]bool)
	var queue []*MergedSection

	mark := func(ms *MergedSection) {
		if ms != nil && !reachable[ms] {
			reachable[ms] = true
			queue = append(queue, ms)
		}
	}

	for _, name := range roots {
		sym := symtab.Lookup(name)
		if sym == nil || sym.RawSym == nil {
			continue
		}
		if ms, ok := layout.SectionByName(sym.RawSym.SectionName); ok {
			mark(ms)
		}
	}

	for len(queue) > 0 {
		ms := queue[0]
		queue = queue[1:]

		for _, p := range ms.Pieces {
			for _, rel := range p.Obj.Relocs {
				if rel.TargetSectionIdx != p.Sec.Index {
					continue
				}
				if int(rel.SymIdx) >= len(p.Obj.Symbols) {
					continue
				}
				sym := p.Obj.Symbols[rel.SymIdx]
				if sym == nil {
					continue
				}

				if sym.SectionIdx >= 0 && sym.SectionIdx < len(p.Obj.Sections) {
					if refSec := p.Obj.Sections[sym.SectionIdx]; refSec != nil {
						mark(secToMerged[secKey{p.Obj, refSec.Name}])
					}
				}

				if sym.Name != "" {
					if ts := symtab.Lookup(sym.Name); ts != nil && ts.RawSym != nil {
						if refMs, ok := layout.SectionByName(ts.RawSym.SectionName); ok {
							mark(refMs)
						}
					}
				}
			}
		}
	}

	kept := layout.Sections[:0]
	for _, ms := range layout.Sections {
		if ms.Flags&SecAlloc == 0 || reachable[ms] {
			kept = append(kept, ms)
		}
	}
	layout.Sections = kept

	layout.secByName = make(map[string]*MergedSection, len(kept))
	for _, ms := range kept {
		layout.secByName[ms.Name] = ms
	}
}