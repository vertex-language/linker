package pe

// OutputType controls what kind of output binary is produced.
type OutputType int

const (
	OutputExec   OutputType = iota // position-dependent executable
	OutputPIE                      // position-independent executable
	OutputShared                   // shared library (.dll)
)

// ── Section ──────────────────────────────────────────────────────────────────

// SectionFlags are format-agnostic section attributes used by the layout engine.
type SectionFlags uint32

const (
	SecAlloc   SectionFlags = 1 << 0 // occupies memory at runtime
	SecWrite   SectionFlags = 1 << 1 // writable at runtime
	SecExec    SectionFlags = 1 << 2 // executable
	SecTLS     SectionFlags = 1 << 3 // thread-local storage
	SecBSS     SectionFlags = 1 << 4 // no file bytes (zero-initialised)
	SecDiscard SectionFlags = 1 << 5 // discardable at runtime (e.g. .reloc)
)

// ObjectSection is one section from an input object file.
type ObjectSection struct {
	Name     string
	Flags    SectionFlags
	Data     []byte
	Size     uint64
	Align    uint64
	RawType  uint32
	RawFlags uint64
	Index    int
	Skip     bool
}

// ── Symbol ───────────────────────────────────────────────────────────────────

// SymBinding mirrors ELF STB_* binding semantics.
type SymBinding uint8

const (
	BindLocal  SymBinding = 0
	BindGlobal SymBinding = 1
	BindWeak   SymBinding = 2
)

// SymType mirrors ELF STT_* type semantics.
type SymType uint8

const (
	SymTypeNone    SymType = 0
	SymTypeObject  SymType = 1
	SymTypeFunc    SymType = 2
	SymTypeSection SymType = 3
	SymTypeFile    SymType = 4
	SymTypeTLS     SymType = 6
)

// SectionIdx sentinels for ObjectSymbol — negative to distinguish from real indices (≥ 0).
const (
	SymSecUndef  = -1 // undefined / imported
	SymSecAbs    = -2 // absolute value
	SymSecCommon = -3 // tentative common block
)

// ObjectSymbol is one symbol from an input object's symbol table.
type ObjectSymbol struct {
	Name        string
	Value       uint64
	Size        uint64
	Binding     SymBinding
	Type        SymType
	Vis         uint8
	SectionIdx  int
	SectionName string
}

// ── Relocation ───────────────────────────────────────────────────────────────

// ObjectReloc is one RELA-style relocation entry from an input object.
type ObjectReloc struct {
	TargetSectionIdx int
	Offset           uint64
	SymIdx           uint32
	Type             uint32
	Addend           int64
}

// ── Object ───────────────────────────────────────────────────────────────────

// Object is a parsed relocatable input object file.
// Sections[0] and Symbols[0] are always nil sentinels.
type Object struct {
	Name     string
	Machine  uint16
	EFlags   uint32
	Sections []*ObjectSection
	Symbols  []*ObjectSymbol
	Relocs   []*ObjectReloc
}

// ── Shared library ───────────────────────────────────────────────────────────

// SharedExport is one symbol exported from a dynamic library.
type SharedExport struct {
	Name    string
	Value   uint64
	Size    uint64
	Binding SymBinding
	Type    SymType
	Version string // export ordinal hint e.g. "@3"; empty if unavailable
}

// SharedLib is a parsed dynamic library (.dll).
type SharedLib struct {
	Name    string
	Soname  string
	Needed  []string
	Rpaths  []string
	Exports map[string]*SharedExport
}

// ── Base relocations ─────────────────────────────────────────────────────────

// BaseRelocSite records a VA at which an absolute pointer was written during
// relocation patching. The patcher accumulates these; the emitter builds .reloc.
type BaseRelocSite struct {
	VA uint64
}