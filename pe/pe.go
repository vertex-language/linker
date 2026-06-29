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

// ImportInfo carries the import/IAT data-directory coordinates to the writer.
type ImportInfo struct {
	ImportDirRVA  uint32
	ImportDirSize uint32
	IATRVA        uint32
	IATSize       uint32
}

// EmitRequest carries all post-link data needed to produce the PE32+ binary.
// The writer reads section placement straight from Layout; the only directory
// data it cannot derive from sections by name is the import/IAT coordinates,
// which arrive in Imports.
type EmitRequest struct {
	Arch       Arch
	OutputType OutputType
	Entry      string
	Soname     string // DLL export name (OutputShared only)
	Needed     []string
	Layout     *Layout
	Symtab     *SymbolTable
	Imports    *ImportInfo // nil when the image has no imports
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
//
// All generated sections (.plt, .got.plt, .idata) are injected before
// AssignLayout so the layout is the single authority for every VAddr the
// writer emits. .reloc is the one exception — its size is known only after
// relocation — and it is placed through Layout.AppendAllocSection, which
// reuses the same contiguity rule. The writer invents no addresses.
func (l *Linker) Link() ([]byte, error) {
	if err := l.walkSharedDeps(); err != nil {
		return nil, fmt.Errorf("link: dep walk: %w", err)
	}

	symtab := NewSymbolTable()
	allObjects := l.collectObjects()
	if err := symtab.Ingest(allObjects, l.archives, l.shared); err != nil {
		return nil, fmt.Errorf("link: symbol resolution: %w", err)
	}
	allObjects = l.collectObjects()

	layout, err := MergeSections(allObjects)
	if err != nil {
		return nil, fmt.Errorf("link: merge: %w", err)
	}

	pltSyms := CollectPLTSymbols(symtab, allObjects)
	GC(layout, symtab, allObjects, l.outputType, l.entry)

	var geom idataGeom
	hasImports := len(pltSyms) > 0
	if hasImports {
		InjectPLTSections(layout, pltSyms)
		l.iatLayout = computeIATLayout(pltSyms)
		if got, ok := layout.SectionByName(".got.plt"); ok {
			extra := uint64(len(l.iatLayout.DLLOrder) * 8) // per-DLL IAT terminators
			got.Data = append(got.Data, make([]byte, extra)...)
			got.Size += extra
		}
		geom = l.injectIdata(layout, symtab, pltSyms)
	}

	if err := AssignLayout(l.outputType, layout, 0); err != nil {
		return nil, fmt.Errorf("link: assign layout: %w", err)
	}
	if err := ResolveSymbolAddresses(symtab, layout); err != nil {
		return nil, fmt.Errorf("link: resolve symbols: %w", err)
	}

	coreBase := coreBaseVA(l.outputType)

	var imports *ImportInfo
	if hasImports {
		if err := PatchPLT(l.newPLTPatcher(), layout, pltSyms); err != nil {
			return nil, fmt.Errorf("link: PLT patch: %w", err)
		}
		idataSec, _ := layout.SectionByName(".idata")
		gotSec, _ := layout.SectionByName(".got.plt")
		idataRVA := toRVA(idataSec.VAddr, coreBase)
		iatBaseRVA := toRVA(gotSec.VAddr, coreBase) + gotReserved*8
		impSize, iatSize := fillImports(idataSec.Data, gotSec.Data, idataRVA, iatBaseRVA, geom)
		imports = &ImportInfo{
			ImportDirRVA:  idataRVA,
			ImportDirSize: impSize,
			IATRVA:        iatBaseRVA,
			IATSize:       iatSize,
		}
	}

	p := l.newPatcher()
	if err := PatchAll(layout, symtab, allObjects, p); err != nil {
		return nil, fmt.Errorf("link: reloc patch: %w", err)
	}

	if l.outputType != OutputExec {
		if brc, ok := p.(BaseRelocCollector); ok {
			if sites := brc.BaseRelocSites(); len(sites) > 0 {
				if relocBytes := buildBaseRelocSection(sites, coreBase); len(relocBytes) > 0 {
					layout.AppendAllocSection(".reloc", relocBytes, SecDiscard, 4)
				}
			}
		}
	}

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

	out, err := emitPE(&EmitRequest{
		Arch:       l.arch,
		OutputType: l.outputType,
		Entry:      l.entry,
		Soname:     l.soname,
		Needed:     needed,
		Layout:     layout,
		Symtab:     symtab,
		Imports:    imports,
	})
	if err != nil {
		return nil, fmt.Errorf("link: emit: %w", err)
	}
	return out, nil
}

// injectIdata appends a sized .idata placeholder before address assignment and
// returns its geometry for the later fill pass.
func (l *Linker) injectIdata(layout *Layout, symtab *SymbolTable, pltSyms []PLTEntry) idataGeom {
	g := computeIdataGeom(symtab, pltSymNames(pltSyms), l.iatLayout)
	sec := &MergedSection{
		Name:  ".idata",
		Flags: SecAlloc | SecWrite,
		Data:  make([]byte, g.size()),
		Size:  uint64(g.size()),
		Align: 8,
	}
	layout.Sections = append(layout.Sections, sec)
	layout.secByName[".idata"] = sec
	return g
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