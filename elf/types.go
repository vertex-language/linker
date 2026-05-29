package elf

// Arch is an ELF machine type (e_machine value).
type Arch = uint16

const (
	ArchAMD64   Arch = 0x3E
	ArchARM64   Arch = 0xB7
	ArchRISCV64 Arch = 0xF3
)

// OutputType controls what kind of output binary is produced.
type OutputType int

const (
	OutputExec   OutputType = iota // position-dependent executable
	OutputPIE                      // position-independent executable
	OutputShared                   // shared library (.so)
)

// SectionFlags are format-agnostic section attributes used by the layout engine.
type SectionFlags uint32

const (
	SecAlloc SectionFlags = 1 << 0 // occupies memory at runtime
	SecWrite SectionFlags = 1 << 1 // writable at runtime
	SecExec  SectionFlags = 1 << 2 // executable
	SecTLS   SectionFlags = 1 << 3 // thread-local storage
	SecBSS   SectionFlags = 1 << 4 // no file bytes (SHT_NOBITS / zero-initialised)
)

// ObjectSection is one section from an input object file.
type ObjectSection struct {
	Name     string
	Flags    SectionFlags // normalised flags used by layout and GC
	Data     []byte       // nil for BSS sections
	Size     uint64       // len(Data) for data sections; total byte count for BSS
	Align    uint64
	RawType  uint32 // ELF SHT_*
	RawFlags uint64 // ELF sh_flags
	Index    int    // position in the section header table (ELF shndx)
	Skip     bool   // true for linker-internal sections (symtab, strtab, rela, group)
}

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

// SectionIdx sentinels for ObjectSymbol — all negative so the sign distinguishes
// special cases from real section indices (≥ 0).
const (
	SymSecUndef  = -1 // SHN_UNDEF
	SymSecAbs    = -2 // SHN_ABS
	SymSecCommon = -3 // SHN_COMMON
)

// ObjectSymbol is one symbol from an input object's symbol table.
type ObjectSymbol struct {
	Name        string
	Value       uint64     // offset within section, or raw value for ABS/common size
	Size        uint64
	Binding     SymBinding
	Type        SymType
	Vis         uint8  // ELF st_other visibility byte
	SectionIdx  int    // index into Object.Sections; use SymSec* sentinels for specials
	SectionName string // decoded section name; "*ABS*" for absolute; "" for undefined
}

// ObjectReloc is one RELA-style relocation entry from an input object.
type ObjectReloc struct {
	TargetSectionIdx int    // Object.Sections index of the section being patched
	Offset           uint64 // byte offset within that section's Data
	SymIdx           uint32 // index into Object.Symbols
	Type             uint32 // arch-specific relocation type
	Addend           int64
}

// Object is a parsed relocatable input object file.
// Sections[0] is always the null section (nil).
// Symbols[0]  is always the null symbol (nil).
type Object struct {
	Name     string
	Machine  uint16
	EFlags   uint32
	Sections []*ObjectSection
	Symbols  []*ObjectSymbol
	Relocs   []*ObjectReloc
}

// SharedExport is one symbol exported from a dynamic library.
type SharedExport struct {
	Name    string
	Value   uint64
	Size    uint64
	Binding SymBinding
	Type    SymType
	Version string // e.g. "GLIBC_2.17"; empty if no versioning
}

// SharedLib is a parsed dynamic library (.so).
type SharedLib struct {
	Name    string
	Soname  string
	Needed  []string
	Rpaths  []string
	Exports map[string]*SharedExport
}