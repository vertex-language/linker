// constants.go — all ELF64 constants used across the sub-package.
package elf

// ── Magic ─────────────────────────────────────────────────────────────────────

const (
	ELFMAG0 = 0x7F
	ELFMAG1 = 'E'
	ELFMAG2 = 'L'
	ELFMAG3 = 'F'
)

const (
	EI_MAG0    = 0
	EI_MAG1    = 1
	EI_MAG2    = 2
	EI_MAG3    = 3
	EI_CLASS   = 4
	EI_DATA    = 5
	EI_VERSION = 6
	EI_OSABI   = 7
	EI_NIDENT  = 16
)

const (
	ELFCLASS64  = 2
	ELFDATA2LSB = 1
	EV_CURRENT  = 1
	ELFOSABI_NONE = 0
)

// ── File type (e_type) ────────────────────────────────────────────────────────

const (
	ET_NONE = 0
	ET_REL  = 1
	ET_EXEC = 2
	ET_DYN  = 3
)

// ── Machine (e_machine) ───────────────────────────────────────────────────────

const (
	EM_X86_64  = uint16(0x3E)
	EM_AARCH64 = uint16(0xB7)
	EM_RISCV   = uint16(0xF3)
)

// ── RISC-V e_flags ────────────────────────────────────────────────────────────

const (
	EF_RISCV_RVC              uint32 = 0x0001
	EF_RISCV_FLOAT_ABI_SOFT   uint32 = 0x0000
	EF_RISCV_FLOAT_ABI_SINGLE uint32 = 0x0002
	EF_RISCV_FLOAT_ABI_DOUBLE uint32 = 0x0004
	EF_RISCV_FLOAT_ABI_QUAD   uint32 = 0x0006
	EF_RISCV_FLOAT_ABI_MASK   uint32 = 0x0006
	EF_RISCV_RVE              uint32 = 0x0008
	EF_RISCV_TSO              uint32 = 0x0010
)

// ── Section header type (sh_type) ────────────────────────────────────────────

const (
	SHT_NULL          = uint32(0)
	SHT_PROGBITS      = uint32(1)
	SHT_SYMTAB        = uint32(2)
	SHT_STRTAB        = uint32(3)
	SHT_RELA          = uint32(4)
	SHT_HASH          = uint32(5)
	SHT_DYNAMIC       = uint32(6)
	SHT_NOTE          = uint32(7)
	SHT_NOBITS        = uint32(8)
	SHT_REL           = uint32(9)
	SHT_DYNSYM        = uint32(11)
	SHT_INIT_ARRAY    = uint32(14)
	SHT_FINI_ARRAY    = uint32(15)
	SHT_PREINIT_ARRAY = uint32(16)
	SHT_GROUP         = uint32(17)
	SHT_SYMTAB_SHNDX  = uint32(18)
	SHT_GNU_HASH      = uint32(0x6FFFFFF6)
	SHT_GNU_VERNEED   = uint32(0x6FFFFFFE)
	SHT_GNU_VERSYM    = uint32(0x6FFFFFFF)
)

// ── Section header flags (sh_flags) ──────────────────────────────────────────

const (
	SHF_WRITE            = uint64(0x001)
	SHF_ALLOC            = uint64(0x002)
	SHF_EXECINSTR        = uint64(0x004)
	SHF_MERGE            = uint64(0x010)
	SHF_STRINGS          = uint64(0x020)
	SHF_INFO_LINK        = uint64(0x040)
	SHF_LINK_ORDER       = uint64(0x080)
	SHF_OS_NONCONFORMING = uint64(0x100)
	SHF_GROUP            = uint64(0x200)
	SHF_TLS              = uint64(0x400)
	SHF_COMPRESSED       = uint64(0x800)
)

// ── Special section indices ───────────────────────────────────────────────────

const (
	SHN_UNDEF     = uint16(0)
	SHN_LORESERVE = uint16(0xFF00)
	SHN_ABS       = uint16(0xFFF1)
	SHN_COMMON    = uint16(0xFFF2)
	SHN_XINDEX    = uint16(0xFFFF)
	SHN_HIRESERVE = uint16(0xFFFF)
)

const PN_XNUM = uint16(0xFFFF)

// ── Program header type (p_type) ──────────────────────────────────────────────

const (
	PT_NULL         = uint32(0)
	PT_LOAD         = uint32(1)
	PT_DYNAMIC      = uint32(2)
	PT_INTERP       = uint32(3)
	PT_NOTE         = uint32(4)
	PT_PHDR         = uint32(6)
	PT_TLS          = uint32(7)
	PT_GNU_EH_FRAME = uint32(0x6474E550)
	PT_GNU_STACK    = uint32(0x6474E551)
	PT_GNU_RELRO    = uint32(0x6474E552)
	PT_GNU_PROPERTY = uint32(0x6474E553)
)

// ── Program header flags (p_flags) ───────────────────────────────────────────

const (
	PF_X = uint32(0x1)
	PF_W = uint32(0x2)
	PF_R = uint32(0x4)
)

// ── Symbol binding ────────────────────────────────────────────────────────────

const (
	STB_LOCAL  = uint8(0)
	STB_GLOBAL = uint8(1)
	STB_WEAK   = uint8(2)
)

// ── Symbol type ───────────────────────────────────────────────────────────────

const (
	STT_NOTYPE    = uint8(0)
	STT_OBJECT    = uint8(1)
	STT_FUNC      = uint8(2)
	STT_SECTION   = uint8(3)
	STT_FILE      = uint8(4)
	STT_COMMON    = uint8(5)
	STT_TLS       = uint8(6)
	STT_GNU_IFUNC = uint8(10)
)

// ── Symbol visibility ─────────────────────────────────────────────────────────

const (
	STV_DEFAULT   = uint8(0)
	STV_HIDDEN    = uint8(2)
	STV_PROTECTED = uint8(3)
)

// ── Symbol version index ──────────────────────────────────────────────────────

const (
	VER_NDX_LOCAL  = uint16(0)
	VER_NDX_GLOBAL = uint16(1)
)

// ── Dynamic tag (d_tag) ───────────────────────────────────────────────────────

const (
	DT_NULL         = int64(0)
	DT_NEEDED       = int64(1)
	DT_PLTRELSZ     = int64(2)
	DT_PLTGOT       = int64(3)
	DT_HASH         = int64(4)
	DT_STRTAB       = int64(5)
	DT_SYMTAB       = int64(6)
	DT_RELA         = int64(7)
	DT_RELASZ       = int64(8)
	DT_RELAENT      = int64(9)
	DT_STRSZ        = int64(10)
	DT_SYMENT       = int64(11)
	DT_INIT         = int64(12)
	DT_FINI         = int64(13)
	DT_SONAME       = int64(14)
	DT_RPATH        = int64(15)
	DT_PLTREL       = int64(20)
	DT_JMPREL       = int64(23)
	DT_RUNPATH      = int64(29)
	DT_GNU_HASH     = int64(0x6FFFFEF5)
	DT_VERSYM       = int64(0x6FFFFFF0)
	DT_VERNEED      = int64(0x6FFFFFFE)
	DT_VERNEEDNUM   = int64(0x6FFFFFFF)
	DT_FLAGS_1      = int64(0x6FFFFFFB)
	DT_NULL_TAG     = int64(0)
)

// ── GNU note types ────────────────────────────────────────────────────────────

const (
	NT_GNU_ABI_TAG  = uint32(1)
	NT_GNU_BUILD_ID = uint32(3)
	NT_GNU_PROPERTY = uint32(5)
)

const (
	GNU_ABI_TAG_LINUX = uint32(0)
)

const (
	GNU_PROPERTY_X86_FEATURE_1_AND  = uint32(0xc0000002)
	GNU_PROPERTY_X86_FEATURE_1_IBT  = uint32(0x1)
	GNU_PROPERTY_X86_FEATURE_1_SHSTK = uint32(0x2)
)