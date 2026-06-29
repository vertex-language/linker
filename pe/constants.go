package pe

// ── Machine types ─────────────────────────────────────────────────────────────

const (
	imageMachineAMD64 = uint16(0x8664)
	imageMachineARM64 = uint16(0xAA64)
)

// ── Optional header magic ─────────────────────────────────────────────────────

const imageNTOptionalHdr64Magic = uint16(0x020B)

// ── COFF file characteristics ─────────────────────────────────────────────────

const (
	imageFileRelocsStripped    = uint16(0x0001)
	imageFileExecutableImage   = uint16(0x0002)
	imageFileLargeAddressAware = uint16(0x0020)
	imageFileDLL               = uint16(0x2000)
)

// ── PE section characteristics ────────────────────────────────────────────────

const (
	imageSCNCntCode              = uint32(0x00000020)
	imageSCNCntInitializedData   = uint32(0x00000040)
	imageSCNCntUninitializedData = uint32(0x00000080)
	imageSCNLnkInfo              = uint32(0x00000200)
	imageSCNLnkRemove            = uint32(0x00000800)
	imageSCNMemDiscardable       = uint32(0x02000000)
	imageSCNMemExecute           = uint32(0x20000000)
	imageSCNMemRead              = uint32(0x40000000)
	imageSCNMemWrite             = uint32(0x80000000)
)

// ── Data directory indices ────────────────────────────────────────────────────

const (
	dirExport    = 0
	dirImport    = 1
	dirBaseReloc = 5
	dirException = 3  // ← add this
	dirIAT       = 12
	dirCount     = 16
)

// ── Subsystem ─────────────────────────────────────────────────────────────────

const (
	imageSubsystemWindowsGUI = uint16(2)
	imageSubsystemWindowsCUI = uint16(3)
)

// ── DLL characteristics ───────────────────────────────────────────────────────

const (
	imageDllCharHighEntropyVA       = uint16(0x0020)
	imageDllCharDynamicBase         = uint16(0x0040)
	imageDllCharNXCompat            = uint16(0x0100)
	imageDllCharNoSEH               = uint16(0x0400)
	imageDllCharTerminalServerAware = uint16(0x8000)
)

// ── COFF symbol storage classes ───────────────────────────────────────────────

const (
	symClassExternal     = uint8(2)
	symClassStatic       = uint8(3)
	symClassWeakExternal = uint8(105)
)

// ── AMD64 COFF relocation types ───────────────────────────────────────────────

const (
	relAMD64Absolute = uint32(0x0000)
	relAMD64Addr64   = uint32(0x0001)
	relAMD64Addr32   = uint32(0x0002)
	relAMD64Addr32NB = uint32(0x0003)
	relAMD64Rel32    = uint32(0x0004)
	relAMD64Rel32_1  = uint32(0x0005)
	relAMD64Rel32_2  = uint32(0x0006)
	relAMD64Rel32_3  = uint32(0x0007)
	relAMD64Rel32_4  = uint32(0x0008)
	relAMD64Rel32_5  = uint32(0x0009)
	relAMD64Section  = uint32(0x000A)
	relAMD64SecRel   = uint32(0x000B)
	relAMD64SecRel7  = uint32(0x000C)
	relAMD64Token    = uint32(0x000D)
)

// ── ARM64 COFF relocation types ───────────────────────────────────────────────

const (
	relARM64Absolute      = uint32(0x0000)
	relARM64Addr32        = uint32(0x0001)
	relARM64Addr32NB      = uint32(0x0002)
	relARM64Branch26      = uint32(0x0003)
	relARM64PagebaseRel21 = uint32(0x0004)
	relARM64Rel21         = uint32(0x0005)
	relARM64PageOffset12A = uint32(0x0006)
	relARM64PageOffset12L = uint32(0x0007)
	relARM64SecRel        = uint32(0x0008)
	relARM64SecRelLow12A  = uint32(0x0009)
	relARM64SecRelHigh12A = uint32(0x000A)
	relARM64SecRelLow12L  = uint32(0x000B)
	relARM64Token         = uint32(0x000C)
	relARM64Section       = uint32(0x000D)
	relARM64Addr64        = uint32(0x000E)
	relARM64Branch19      = uint32(0x000F)
	relARM64Branch14      = uint32(0x0010)
	relARM64Rel32         = uint32(0x0011)
)

// ── Base relocation entry types ───────────────────────────────────────────────

const (
	baseRelocAbsolute = 0
	baseRelocDir64    = 10
)

// ── Structure sizes ───────────────────────────────────────────────────────────

const (
	sizeDOSStub        = 64
	sizePESig          = 4
	sizeCOFFHdr        = 20
	sizeOptHdr64       = 240
	sizeSectionHdr     = 40
	sizeImportDesc     = 20
	sizeBaseRelocBlock = 8
)

// ── PE file / section alignment ───────────────────────────────────────────────

const (
	peFileAlign = uint64(0x200)
	peSectAlign = uint64(0x1000)
)

// imageBaseFor returns the preferred PE image base for the given output type.
func imageBaseFor(ot OutputType) uint64 {
	switch ot {
	case OutputExec:
		return 0x0000000000400000
	case OutputPIE:
		return 0x0000000140000000
	default: // OutputShared
		return 0x0000000010000000
	}
}

// coreBaseVA returns the base VA that AssignLayout used.
func coreBaseVA(ot OutputType) uint64 {
	if ot == OutputExec {
		return 0x400000
	}
	return 0
}

// toRVA converts a core-layout virtual address to a PE RVA.
func toRVA(va, base uint64) uint32 { return uint32(va - base) }