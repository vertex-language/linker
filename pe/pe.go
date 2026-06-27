package pe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Arch identifies the target CPU architecture for PE32+ output.
type Arch uint8

const (
	ArchAMD64 Arch = 1
	ArchARM64 Arch = 2
)

// EmitRequest carries all post-link data needed to produce the PE32+ binary.
type EmitRequest struct {
	Arch       Arch
	OutputType OutputType
	Entry      string
	Soname     string // DLL export name (OutputShared only)
	Needed     []string
	Layout     *Layout
	Symtab     *SymbolTable
	PLTSyms    []string
	BaseRelocs []BaseRelocSite
}

// Linker is the self-contained PE32+ linker.
type Linker struct {
	arch       Arch
	outputType OutputType
	entry      string
	soname     string
	libPaths   []string

	objects     []*Object
	archives    []*Archive
	shared      []*SharedLib
	extraNeeded []string

	iatLayout *IATLayout // computed during Link
}

// NewLinker returns a PE32+ linker for the given architecture.
// Default output type is OutputExec with entry point "mainCRTStartup".
func NewLinker(arch Arch) *Linker {
	switch arch {
	case ArchAMD64, ArchARM64:
	default:
		panic(fmt.Sprintf("pe: unsupported arch %d", arch))
	}
	l := &Linker{arch: arch}
	l.SetOutputType(OutputExec)
	l.SetEntryPoint("mainCRTStartup")
	return l
}

func (l *Linker) SetOutputType(t OutputType) { l.outputType = t }
func (l *Linker) SetEntryPoint(name string)  { l.entry = name }
func (l *Linker) SetSoname(name string)      { l.soname = name }
func (l *Linker) AddLibraryPath(path string) { l.libPaths = append(l.libPaths, path) }
func (l *Linker) OutputType() OutputType     { return l.outputType }

// AddSONeeded marks soname as an explicit DT_NEEDED dependency.
func (l *Linker) AddSONeeded(soname string) {
	l.extraNeeded = append(l.extraNeeded, soname)
}

// AddObject parses and registers a COFF relocatable object file.
func (l *Linker) AddObject(name string, data []byte) error {
	obj, err := parseObject(name, data)
	if err != nil {
		return fmt.Errorf("AddObject %q: %w", name, err)
	}
	l.objects = append(l.objects, obj)
	return nil
}

// AddArchive parses and registers a static archive (.lib / .a).
func (l *Linker) AddArchive(name string, data []byte) error {
	ar, err := ParseArchive(name, data, parseObject)
	if err != nil {
		return fmt.Errorf("AddArchive %q: %w", name, err)
	}
	l.archives = append(l.archives, ar)
	return nil
}

// AddDynamicLibrary parses and registers a PE32+ DLL as an import library.
func (l *Linker) AddDynamicLibrary(name string, data []byte) error {
	lib, err := parseDLL(name, data)
	if err != nil {
		return fmt.Errorf("AddDynamicLibrary %q: %w", name, err)
	}
	l.shared = append(l.shared, lib)
	return nil
}

// Link runs all linking phases and returns the finished PE32+ binary.
func (l *Linker) Link() ([]byte, error) {
	// Phase 1: transitive DLL dependency walk.
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

	// Phase 3c: PE IAT layout and .got.plt resize.
	if len(pltSyms) > 0 {
		if err := l.injectIATSections(layout, pltSyms); err != nil {
			return nil, fmt.Errorf("link: inject IAT: %w", err)
		}
	}

	// Phase 4: dead-code elimination.
	GC(layout, symtab, allObjects, l.outputType, l.entry)

	// Phase 5: virtual address and file-offset assignment.
	if err := AssignLayout(l.outputType, layout, 0); err != nil {
		return nil, fmt.Errorf("link: assign layout: %w", err)
	}

	// Phase 6: resolve symbol virtual addresses.
	if err := ResolveSymbolAddresses(symtab, layout); err != nil {
		return nil, fmt.Errorf("link: resolve symbols: %w", err)
	}

	// Phase 7: write import thunks and assign stub VAddrs to shared symbols.
	if len(pltSyms) > 0 {
		if err := PatchPLT(l.newPLTPatcher(), layout, pltSyms); err != nil {
			return nil, fmt.Errorf("link: PLT patch: %w", err)
		}
	}

	// Phase 8: relocation patching.
	p := l.newPatcher()
	if err := PatchAll(layout, symtab, allObjects, p); err != nil {
		return nil, fmt.Errorf("link: reloc patch: %w", err)
	}

	// Phase 8b: collect base-relocation sites for .reloc section.
	var baseRelocs []BaseRelocSite
	if brc, ok := p.(BaseRelocCollector); ok {
		baseRelocs = brc.BaseRelocSites()
	}

	// Phase 9: collect import dependencies.
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

	// Phase 10: emit PE32+ binary.
	req := &EmitRequest{
		Arch:       l.arch,
		OutputType: l.outputType,
		Entry:      l.entry,
		Soname:     l.soname,
		Needed:     needed,
		Layout:     layout,
		Symtab:     symtab,
		PLTSyms:    pltSymNames(pltSyms),
		BaseRelocs: baseRelocs,
	}
	out, err := emitPE(l.iatLayout, req)
	if err != nil {
		return nil, fmt.Errorf("link: emit: %w", err)
	}
	return out, nil
}

// injectIATSections computes the DLL-grouped IATLayout and resizes .got.plt
// to include per-DLL null-terminator slots.
func (l *Linker) injectIATSections(layout *Layout, pltSyms []PLTEntry) error {
	l.iatLayout = computeIATLayout(pltSyms)
	got, ok := layout.SectionByName(".got.plt")
	if !ok {
		return nil
	}
	extra := uint64(len(l.iatLayout.DLLOrder) * 8)
	got.Data = append(got.Data, make([]byte, extra)...)
	got.Size += extra
	return nil
}

func (l *Linker) newPatcher() Patcher {
	base := coreBaseVA(l.outputType)
	switch l.arch {
	case ArchAMD64:
		return &amd64Patcher{coreBase: base}
	default:
		return &arm64Patcher{coreBase: base}
	}
}

func (l *Linker) newPLTPatcher() PLTPatcher {
	switch l.arch {
	case ArchAMD64:
		return &amd64PLTPatcher{iatLayout: l.iatLayout}
	default:
		return &arm64PLTPatcher{iatLayout: l.iatLayout}
	}
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
			// API Set virtual DLLs (api-ms-win-* and ext-ms-win-*) have no
			// real file on disk — the Windows loader resolves them at runtime
			// via apisetschema.dll. Skip them during the dep walk.
			if isAPISet(soname) {
				continue
			}
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

// isAPISet reports whether soname is a Windows API Set virtual DLL.
// These have no real file on disk; the OS loader resolves them at runtime
// through the API Set schema. Attempting to open them as files always fails.
func isAPISet(soname string) bool {
	s := strings.ToLower(soname)
	return strings.HasPrefix(s, "api-ms-win-") ||
		strings.HasPrefix(s, "ext-ms-win-")
}

func (l *Linker) findShared(soname string, rpaths []string) (*SharedLib, error) {
	searchDirs := append(append([]string{}, rpaths...), l.libPaths...)
	searchDirs = append(searchDirs,
		`C:\Windows\System32`,
		`C:\Windows\SysWOW64`,
		`C:\Windows\System`,
	)
	for _, dir := range searchDirs {
		path := filepath.Join(dir, soname)
		data, err := os.ReadFile(path)
		if err == nil {
			return parseDLL(soname, data)
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