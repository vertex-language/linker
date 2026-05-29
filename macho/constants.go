package macho

// ── Magic numbers ─────────────────────────────────────────────────────────────

const (
	MH_MAGIC_64 = 0xFEEDFACF // 64-bit Mach-O little-endian
	MH_CIGAM_64 = 0xCFFAEDFE // byte-swapped (big-endian host)

	// CPU types (include the 64-bit flag 0x01000000)
	CPU_TYPE_AMD64 = int32(0x01000007) // CPU_TYPE_X86_64
	CPU_TYPE_ARM64 = int32(0x0100000C) // CPU_TYPE_ARM | ABI64

	// CPU subtypes
	CPU_SUBTYPE_AMD64_ALL = int32(3)
	CPU_SUBTYPE_ARM64_ALL = int32(0)
	CPU_SUBTYPE_ARM64E    = int32(2) // arm64e (PAC)
)

// ── File types ────────────────────────────────────────────────────────────────

const (
	MH_OBJECT  = uint32(0x1) // relocatable object
	MH_EXECUTE = uint32(0x2) // demand-paged executable
	MH_DYLIB   = uint32(0x6) // dynamically bound shared library
	MH_BUNDLE  = uint32(0x8) // dynamically bound bundle file
)

// ── Mach-O header flags ───────────────────────────────────────────────────────

const (
	MH_NOUNDEFS          = uint32(0x00000001)
	MH_DYLDLINK          = uint32(0x00000004)
	MH_BINDATLOAD        = uint32(0x00000008)
	MH_TWOLEVEL          = uint32(0x00000080)
	MH_PIE               = uint32(0x00200000)
	MH_NO_HEAP_EXECUTION = uint32(0x01000000)
)

// ── Load command numbers ──────────────────────────────────────────────────────

const (
	LC_SEGMENT_64         = uint32(0x19)
	LC_SYMTAB             = uint32(0x02)
	LC_DYSYMTAB           = uint32(0x0B)
	LC_LOAD_DYLINKER      = uint32(0x0E)
	LC_LOAD_DYLIB         = uint32(0x0C)
	LC_LOAD_WEAK_DYLIB    = uint32(0x18 | 0x80000000)
	LC_ID_DYLIB           = uint32(0x0D)
	LC_RPATH              = uint32(0x1C | 0x80000000)
	LC_UUID               = uint32(0x1B)
	LC_BUILD_VERSION      = uint32(0x32)
	LC_SOURCE_VERSION     = uint32(0x2A)
	LC_MAIN               = uint32(0x28 | 0x80000000)
	LC_DYLD_INFO_ONLY     = uint32(0x22 | 0x80000000)
	LC_FUNCTION_STARTS    = uint32(0x26)
	LC_DATA_IN_CODE       = uint32(0x29)
	LC_CODE_SIGNATURE     = uint32(0x1D)
)

// ── VM protection bits ────────────────────────────────────────────────────────

const (
	VM_PROT_NONE    = int32(0x0)
	VM_PROT_READ    = int32(0x1)
	VM_PROT_WRITE   = int32(0x2)
	VM_PROT_EXECUTE = int32(0x4)
	VM_PROT_ALL     = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
)

// ── Section types (low 8 bits of section flags) ───────────────────────────────

const (
	S_REGULAR                  = uint32(0x0)
	S_ZEROFILL                 = uint32(0x1)
	S_CSTRING_LITERALS         = uint32(0x2)
	S_4BYTE_LITERALS           = uint32(0x3)
	S_8BYTE_LITERALS           = uint32(0x4)
	S_LITERAL_POINTERS         = uint32(0x5)
	S_NON_LAZY_SYMBOL_POINTERS = uint32(0x6)
	S_LAZY_SYMBOL_POINTERS     = uint32(0x7)
	S_SYMBOL_STUBS             = uint32(0x8)
	S_MOD_INIT_FUNC_POINTERS   = uint32(0x9)
	S_MOD_TERM_FUNC_POINTERS   = uint32(0xA)
)

// ── Section attribute flags (high 24 bits) ────────────────────────────────────

const (
	S_ATTR_PURE_INSTRUCTIONS  = uint32(0x80000000)
	S_ATTR_SOME_INSTRUCTIONS  = uint32(0x00000400)
	S_ATTR_EXT_RELOC          = uint32(0x00000200)
	S_ATTR_LOC_RELOC          = uint32(0x00000100)
)

// ── nlist_64 n_type masks and values ─────────────────────────────────────────

const (
	N_STAB = uint8(0xE0) // mask: stab (debug) entry
	N_PEXT = uint8(0x10) // private external
	N_TYPE = uint8(0x0E) // mask: symbol type
	N_EXT  = uint8(0x01) // external (global)

	N_UNDF = uint8(0x0) // undefined / imported
	N_ABS  = uint8(0x2) // absolute value
	N_SECT = uint8(0xE) // defined in section
	N_INDR = uint8(0xA) // indirect

	NO_SECT = uint8(0) // sentinel: not in any section
)

// ── nlist_64 n_desc flags ─────────────────────────────────────────────────────

const (
	N_WEAK_REF = uint16(0x0040) // symbol may be missing (weak import)
	N_WEAK_DEF = uint16(0x0080) // coalesced symbol is a weak definition
)

// ── Relocation types — AMD64 ──────────────────────────────────────────────────

const (
	X86_64_RELOC_UNSIGNED   = uint32(0)
	X86_64_RELOC_SIGNED     = uint32(1)
	X86_64_RELOC_BRANCH     = uint32(2)
	X86_64_RELOC_GOT_LOAD   = uint32(3)
	X86_64_RELOC_GOT        = uint32(4)
	X86_64_RELOC_SUBTRACTOR = uint32(5)
	X86_64_RELOC_SIGNED_1   = uint32(6)
	X86_64_RELOC_SIGNED_2   = uint32(7)
	X86_64_RELOC_SIGNED_4   = uint32(8)
	X86_64_RELOC_TLV        = uint32(9)
)

// ── Relocation types — ARM64 ──────────────────────────────────────────────────

const (
	ARM64_RELOC_UNSIGNED            = uint32(0)
	ARM64_RELOC_SUBTRACTOR          = uint32(1)
	ARM64_RELOC_BRANCH26            = uint32(2)
	ARM64_RELOC_PAGE21              = uint32(3)
	ARM64_RELOC_PAGEOFF12           = uint32(4)
	ARM64_RELOC_GOT_LOAD_PAGE21     = uint32(5)
	ARM64_RELOC_GOT_LOAD_PAGEOFF12  = uint32(6)
	ARM64_RELOC_POINTER_TO_GOT      = uint32(7)
	ARM64_RELOC_TLVP_LOAD_PAGE21    = uint32(8)
	ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = uint32(9)
	ARM64_RELOC_ADDEND              = uint32(10)
)

// ── LC_BUILD_VERSION platforms ────────────────────────────────────────────────

const (
	PLATFORM_MACOS   = uint32(1)
	PLATFORM_IOS     = uint32(2)
	PLATFORM_TVOS    = uint32(3)
	PLATFORM_WATCHOS = uint32(4)
)

// ── Dyld rebase opcodes ───────────────────────────────────────────────────────

const (
	REBASE_TYPE_POINTER = uint8(1)

	REBASE_OPCODE_DONE                               = uint8(0x00)
	REBASE_OPCODE_SET_TYPE_IMM                       = uint8(0x10)
	REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        = uint8(0x20)
	REBASE_OPCODE_ADD_ADDR_ULEB                      = uint8(0x30)
	REBASE_OPCODE_ADD_ADDR_IMM_SCALED                = uint8(0x40)
	REBASE_OPCODE_DO_REBASE_IMM_TIMES                = uint8(0x50)
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES               = uint8(0x60)
	REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB            = uint8(0x70)
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = uint8(0x80)
)

// ── Dyld bind opcodes ─────────────────────────────────────────────────────────

const (
	BIND_TYPE_POINTER = uint8(1)

	BIND_SPECIAL_DYLIB_SELF            = 0
	BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1
	BIND_SPECIAL_DYLIB_FLAT_LOOKUP     = -2

	BIND_SYMBOL_FLAGS_WEAK_IMPORT = uint8(0x1)

	BIND_OPCODE_DONE                              = uint8(0x00)
	BIND_OPCODE_SET_DYLIB_ORDINAL_IMM             = uint8(0x10)
	BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB            = uint8(0x20)
	BIND_OPCODE_SET_DYLIB_SPECIAL_IMM             = uint8(0x30)
	BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM      = uint8(0x40)
	BIND_OPCODE_SET_TYPE_IMM                       = uint8(0x50)
	BIND_OPCODE_SET_ADDEND_SLEB                    = uint8(0x60)
	BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        = uint8(0x70)
	BIND_OPCODE_ADD_ADDR_ULEB                      = uint8(0x80)
	BIND_OPCODE_DO_BIND                            = uint8(0x90)
	BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB              = uint8(0xA0)
	BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED        = uint8(0xB0)
	BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB   = uint8(0xC0)
)

// ── Export symbol flags ───────────────────────────────────────────────────────

const (
	EXPORT_SYMBOL_FLAGS_KIND_REGULAR      = uint64(0x00)
	EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = uint64(0x01)
	EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE     = uint64(0x02)
	EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION   = uint64(0x04)
	EXPORT_SYMBOL_FLAGS_REEXPORT          = uint64(0x08)
	EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = uint64(0x10)
)

// ── On-disk struct sizes ──────────────────────────────────────────────────────

const (
	machHeaderSize64    = 32
	segCmdSize64        = 72
	sectSize64          = 80
	symtabCmdSize       = 24
	dysymtabCmdSize     = 80
	dylinkerCmdMinSize  = 12
	dylibCmdMinSize     = 24
	entryPointCmdSize   = 24
	dyldInfoCmdSize     = 48
	buildVersionCmdSize = 24
	sourceVersionCmdSize = 16
	uuidCmdSize         = 24
	rpathCmdMinSize     = 12
	nlist64Size         = 16
	relocEntrySize      = 8
)