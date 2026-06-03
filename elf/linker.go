// linker.go — ELF64 linker entry point and main Link pipeline.
package elf

import (
	"fmt"
	"os"
	"path/filepath"
)

// EmitRequest carries all post-link data needed to produce the output binary.
type EmitRequest struct {
	Arch       Arch
	OutputType OutputType
	Entry      string
	Interp     string
	Soname     string
	Rpath      string
	Needed     []string
	Layout     *Layout
	Symtab     *SymbolTable
	PLTSyms    []string // PLT symbol names in stub order
}

// Linker is the ELF64 linker.
type Linker struct {
	arch       Arch
	outputType OutputType
	entry      string
	interp     string
	soname     string
	rpath      string
	libPaths   []string

	objects     []*Object
	archives    []*Archive
	shared      []*SharedLib
	extraNeeded []string
}

// NewLinker returns a Linker configured for the given ELF machine architecture.
// The interpreter path is set to the standard dynamic linker for that arch.
func NewLinker(arch Arch) *Linker {
	l := &Linker{arch: arch}
	if interp := defaultInterp(arch); interp != "" {
		l.interp = interp
	}
	return l
}

func (l *Linker) SetOutputType(t OutputType) { l.outputType = t }
func (l *Linker) SetEntryPoint(name string)  { l.entry = name }
func (l *Linker) SetInterp(path string)      { l.interp = path }
func (l *Linker) SetSoname(name string)      { l.soname = name }
func (l *Linker) SetRpath(path string)       { l.rpath = path }
func (l *Linker) AddLibraryPath(path string) { l.libPaths = append(l.libPaths, path) }
func (l *Linker) OutputType() OutputType     { return l.outputType }

func (l *Linker) AddSONeeded(soname string) {
	l.extraNeeded = append(l.extraNeeded, soname)
}

func (l *Linker) AddObject(name string, data []byte) error {
	obj, err := ParseObject(name, data)
	if err != nil {
		return fmt.Errorf("AddObject %q: %w", name, err)
	}
	l.objects = append(l.objects, obj)
	return nil
}

func (l *Linker) AddArchive(name string, data []byte) error {
	ar, err := ParseArchive(name, data, ParseObject)
	if err != nil {
		return fmt.Errorf("AddArchive %q: %w", name, err)
	}
	l.archives = append(l.archives, ar)
	return nil
}

func (l *Linker) AddDynamicLibrary(name string, data []byte) error {
	lib, err := ParseSharedLib(name, data)
	if err != nil {
		return fmt.Errorf("AddDynamicLibrary %q: %w", name, err)
	}
	l.shared = append(l.shared, lib)
	return nil
}

// Link runs all linking phases and returns the native binary bytes.
func (l *Linker) Link() ([]byte, error) {
	// Default entry point for position-dependent and PIE executables.
	// Shared libraries have no entry point and keep l.entry == "".
	if l.outputType != OutputShared && l.entry == "" {
		l.entry = "_start"
	}

	// Phase 1: transitive shared-library dependency walk.
	if err := l.walkSharedDeps(); err != nil {
		return nil, fmt.Errorf("link: dep walk: %w", err)
	}

	// Phase 2: symbol resolution.
	symtab := NewSymbolTable()
	allObjects := l.collectObjects()
	if err := symtab.Ingest(allObjects, l.archives, l.shared); err != nil {
		return nil, fmt.Errorf("link: symbol resolution: %w", err)
	}
	allObjects = l.collectObjects()

	// Phase 3: section merging.
	layout, err := MergeSections(allObjects)
	if err != nil {
		return nil, fmt.Errorf("link: merge: %w", err)
	}

	// Phase 3b: PLT injection.
	pltSyms := CollectPLTSymbols(symtab, allObjects)
	if len(pltSyms) > 0 {
		InjectPLTSections(layout, pltSyms)
	}

	// Phase 4: dead-code elimination.
	GC(layout, symtab, allObjects, l.outputType, l.entry)

	// Phase 5: virtual address and file-offset assignment.
	if err := AssignLayout(l.outputType, layout, 0); err != nil {
		return nil, fmt.Errorf("link: layout: %w", err)
	}

	// Phase 6: resolve symbol virtual addresses.
	if err := ResolveSymbolAddresses(symtab, layout); err != nil {
		return nil, fmt.Errorf("link: resolve symbols: %w", err)
	}

	// Phase 7: write PLT stubs and assign stub VAddrs to shared symbols.
	if len(pltSyms) > 0 {
		pp := &elfPLTPatcher{arch: l.arch}
		if err := PatchPLT(pp, layout, pltSyms); err != nil {
			return nil, fmt.Errorf("link: PLT patch: %w", err)
		}
	}

	// Phase 8: relocation patching.
	patcher := &elfPatcher{arch: l.arch}
	if err := PatchAll(layout, symtab, allObjects, patcher); err != nil {
		return nil, fmt.Errorf("link: reloc patch: %w", err)
	}

	// Phase 9: collect DT_NEEDED / import list.
	needed := collectNeeded(l.shared)
	seen := make(map[string]bool, len(needed))
	for _, n := range needed {
		seen[n] = true
	}
	for _, n := range l.extraNeeded {
		if !seen[n] {
			seen[n] = true
			needed = append(needed, n)
		}
	}

	// Phase 10: emit the binary.
	req := &EmitRequest{
		Arch:       l.arch,
		OutputType: l.outputType,
		Entry:      l.entry,
		Interp:     l.interp,
		Soname:     l.soname,
		Rpath:      l.rpath,
		Needed:     needed,
		Layout:     layout,
		Symtab:     symtab,
		PLTSyms:    pltSymNames(pltSyms),
	}
	out, err := Emit(req)
	if err != nil {
		return nil, fmt.Errorf("link: emit: %w", err)
	}
	return out, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (l *Linker) walkSharedDeps() error {
	seen := make(map[string]bool)
	for _, s := range l.shared {
		seen[s.Soname] = true
	}
	queue := make([]*SharedLib, len(l.shared))
	copy(queue, l.shared)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, soname := range cur.Needed {
			if seen[soname] {
				continue
			}
			seen[soname] = true
			dep, err := l.findShared(soname, cur.Rpaths)
			if err != nil {
				return fmt.Errorf("loading %s (needed by %s): %w", soname, cur.Soname, err)
			}
			l.shared = append(l.shared, dep)
			queue = append(queue, dep)
		}
	}
	return nil
}

func (l *Linker) findShared(soname string, rpaths []string) (*SharedLib, error) {
	searchDirs := append(append([]string{}, rpaths...), l.libPaths...)
	searchDirs = append(searchDirs,
		"/usr/lib", "/usr/local/lib",
		"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
		"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
		"/lib64", "/usr/lib64", "/lib",
	)
	for _, dir := range searchDirs {
		path := filepath.Join(dir, soname)
		data, err := os.ReadFile(path)
		if err == nil {
			return ParseSharedLib(soname, data)
		}
	}
	return nil, fmt.Errorf("shared library %q not found", soname)
}

func (l *Linker) collectObjects() []*Object {
	out := make([]*Object, len(l.objects))
	copy(out, l.objects)
	for _, ar := range l.archives {
		for _, m := range ar.Members {
			if m.obj != nil {
				out = append(out, m.obj)
			}
		}
	}
	return out
}

func collectNeeded(libs []*SharedLib) []string {
	seen := make(map[string]bool)
	var out []string
	for _, lib := range libs {
		if !seen[lib.Soname] {
			seen[lib.Soname] = true
			out = append(out, lib.Soname)
		}
	}
	return out
}

func pltSymNames(syms []PLTEntry) []string {
	if len(syms) == 0 {
		return nil
	}
	out := make([]string, len(syms))
	for i, s := range syms {
		out[i] = s.Name
	}
	return out
}

func defaultInterp(arch Arch) string {
	switch arch {
	case ArchAMD64:
		return "/lib64/ld-linux-x86-64.so.2"
	case ArchARM64:
		return "/lib/ld-linux-aarch64.so.1"
	case ArchRISCV64:
		return "/lib/ld-linux-riscv64-lp64d.so.1"
	}
	return ""
}