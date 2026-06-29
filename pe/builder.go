package pe

import (
	"encoding/binary"
	"sort"
)

var dosStub = [sizeDOSStub]byte{
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
	0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
}

type peSection struct {
	name    string
	ms      *MergedSection
	data    []byte
	rva     uint32
	vsize   uint32
	rawSize uint32
	fileOff uint32
	chars   uint32
}

// emitPE serialises an already-laid-out image. It is mechanical: section RVAs
// come straight from Layout, file offsets are packed in a single pass, and
// data directories are looked up from placed sections by name. It invents no
// addresses and emits exactly the set of allocatable sections the layout placed.
func emitPE(req *EmitRequest) ([]byte, error) {
	imgBase := imageBaseFor(req.OutputType)
	coreBase := coreBaseVA(req.OutputType)
	machine := uint16(imageMachineAMD64)
	if req.Arch == ArchARM64 {
		machine = imageMachineARM64
	}

	// ── 1. Every allocatable section, in layout-assigned address order ────
	var sects []*peSection
	for _, ms := range req.Layout.Sections {
		if ms.Flags&SecAlloc == 0 {
			continue
		}
		ps := &peSection{
			name:  truncateName(ms.Name),
			ms:    ms,
			data:  ms.Data,
			rva:   toRVA(ms.VAddr, coreBase),
			vsize: uint32(ms.Size),
			chars: secChars(ms.Flags),
		}
		if ms.Flags&SecBSS != 0 {
			ps.data, ps.rawSize = nil, 0
		} else {
			ps.rawSize = uint32(alignUp64(uint64(len(ms.Data)), peFileAlign))
		}
		sects = append(sects, ps)
	}
	sort.Slice(sects, func(i, j int) bool { return sects[i].rva < sects[j].rva })

	// ── 2. File offsets — the writer's only placement responsibility ──────
	nSections := len(sects)
	headerSize := sizeDOSStub + sizePESig + sizeCOFFHdr + sizeOptHdr64 + nSections*sizeSectionHdr
	fileOff := alignUp32(uint32(headerSize), uint32(peFileAlign))
	for _, ps := range sects {
		if ps.rawSize == 0 {
			ps.fileOff = 0
			continue
		}
		ps.fileOff = fileOff
		fileOff += ps.rawSize
	}

	// ── 3. Image metrics ──────────────────────────────────────────────────
	sizeOfHeaders := uint32(alignUp64(uint64(headerSize), peFileAlign))
	sizeOfImage := sizeOfHeaders
	for _, ps := range sects {
		if end := alignUp32(ps.rva+ps.vsize, uint32(peSectAlign)); end > sizeOfImage {
			sizeOfImage = end
		}
	}

	entryRVA := uint32(0)
	if req.Entry != "" {
		if sym := req.Symtab.Lookup(req.Entry); sym != nil && sym.VAddr != 0 {
			entryRVA = toRVA(sym.VAddr, coreBase)
		}
	}

	baseOfCode := uint32(0)
	for _, ps := range sects {
		if ps.chars&imageSCNMemExecute != 0 {
			baseOfCode = ps.rva
			break
		}
	}

	var sizeCode, sizeInitData, sizeUninitData uint32
	for _, ps := range sects {
		switch {
		case ps.chars&imageSCNCntCode != 0:
			sizeCode += ps.rawSize
		case ps.chars&imageSCNCntUninitializedData != 0:
			sizeUninitData += ps.vsize
		case ps.chars&imageSCNCntInitializedData != 0:
			sizeInitData += ps.rawSize
		}
	}

	// ── 4. Data directories, derived from placed sections by name ─────────
	var importDirRVA, importDirSize, iatDirRVA, iatDirSize uint32
	if req.Imports != nil {
		importDirRVA = req.Imports.ImportDirRVA
		importDirSize = req.Imports.ImportDirSize
		iatDirRVA = req.Imports.IATRVA
		iatDirSize = req.Imports.IATSize
	}

	var exceptionDirRVA, exceptionDirSize, relocDirRVA, relocDirSize uint32
	if ps := findSect(sects, ".pdata"); ps != nil {
		exceptionDirRVA, exceptionDirSize = ps.rva, ps.vsize
	}
	relocPresent := false
	if ps := findSect(sects, ".reloc"); ps != nil {
		relocDirRVA, relocDirSize, relocPresent = ps.rva, ps.vsize, true
	}

	fileChars := imageFileExecutableImage | imageFileLargeAddressAware
	if req.OutputType == OutputExec {
		fileChars |= imageFileRelocsStripped
	}
	if req.OutputType == OutputShared {
		fileChars |= imageFileDLL
	}

	// Advertise ASLR only when a .reloc section was actually emitted: a PIE/DLL
	// claiming HIGH_ENTROPY_VA with no relocation table is rejected by the
	// loader with ERROR_BAD_EXE_FORMAT.
	dllChars := imageDllCharNXCompat | imageDllCharTerminalServerAware
	if req.OutputType != OutputExec && relocPresent {
		dllChars |= imageDllCharHighEntropyVA | imageDllCharDynamicBase
	}

	// ── 5. Serialise ──────────────────────────────────────────────────────
	buf := make([]byte, int(fileOff))
	put := func(off int, b []byte) { copy(buf[off:], b) }
	le16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(buf[off:], v) }
	le32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }
	le64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(buf[off:], v) }

	put(0, dosStub[:])
	buf[0x40], buf[0x41] = 'P', 'E'

	coff := 0x44
	le16(coff+0, machine)
	le16(coff+2, uint16(nSections))
	le32(coff+4, 0)
	le32(coff+8, 0)
	le32(coff+12, 0)
	le16(coff+16, sizeOptHdr64)
	le16(coff+18, uint16(fileChars))

	opt := coff + sizeCOFFHdr
	le16(opt+0, imageNTOptionalHdr64Magic)
	buf[opt+2] = 1
	buf[opt+3] = 0
	le32(opt+4, sizeCode)
	le32(opt+8, sizeInitData)
	le32(opt+12, sizeUninitData)
	le32(opt+16, entryRVA)
	le32(opt+20, baseOfCode)

	ws := opt + 24
	le64(ws+0, imgBase)
	le32(ws+8, uint32(peSectAlign))
	le32(ws+12, uint32(peFileAlign))
	le16(ws+16, 6)
	le16(ws+18, 1) // MinorOSVersion: 6.1 = Windows 7 minimum
	le16(ws+20, 0)
	le16(ws+22, 0)
	le16(ws+24, 6)
	le16(ws+26, 1) // MinorSubsystemVersion: 6.1 = Windows 7 minimum
	le32(ws+28, 0)
	le32(ws+32, sizeOfImage)
	le32(ws+36, sizeOfHeaders)
	le32(ws+40, 0)
	le16(ws+44, imageSubsystemWindowsCUI)
	le16(ws+46, uint16(dllChars))
	le64(ws+48, 0x100000)
	le64(ws+56, 0x1000)
	le64(ws+64, 0x100000)
	le64(ws+72, 0x1000)
	le32(ws+80, 0)
	le32(ws+84, dirCount)

	dd := opt + 112
	le32(dd+dirImport*8, importDirRVA)
	le32(dd+dirImport*8+4, importDirSize)
	le32(dd+dirException*8, exceptionDirRVA)
	le32(dd+dirException*8+4, exceptionDirSize)
	le32(dd+dirBaseReloc*8, relocDirRVA)
	le32(dd+dirBaseReloc*8+4, relocDirSize)
	le32(dd+dirIAT*8, iatDirRVA)
	le32(dd+dirIAT*8+4, iatDirSize)

	shBase := opt + sizeOptHdr64
	for i, ps := range sects {
		sh := shBase + i*sizeSectionHdr
		var nameBytes [8]byte
		copy(nameBytes[:], ps.name)
		put(sh, nameBytes[:])
		le32(sh+8, ps.vsize)
		le32(sh+12, ps.rva)
		le32(sh+16, ps.rawSize)
		le32(sh+20, ps.fileOff)
		le32(sh+24, 0)
		le32(sh+28, 0)
		le16(sh+32, 0)
		le16(sh+34, 0)
		le32(sh+36, ps.chars)
	}

	for _, ps := range sects {
		if ps.rawSize == 0 || len(ps.data) == 0 {
			continue
		}
		copy(buf[ps.fileOff:ps.fileOff+ps.rawSize], ps.data)
	}

	return buf, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func findSect(sects []*peSection, name string) *peSection {
	for _, ps := range sects {
		if ps.ms != nil && ps.ms.Name == name {
			return ps
		}
	}
	return nil
}

func truncateName(name string) string {
	if len(name) > 8 {
		return name[:8]
	}
	return name
}

func secChars(f SectionFlags) uint32 {
	var ch uint32
	switch {
	case f&SecExec != 0:
		ch = imageSCNCntCode | imageSCNMemExecute | imageSCNMemRead
	case f&SecBSS != 0:
		ch = imageSCNCntUninitializedData | imageSCNMemRead
		if f&SecWrite != 0 {
			ch |= imageSCNMemWrite
		}
	default:
		ch = imageSCNCntInitializedData | imageSCNMemRead
		if f&SecWrite != 0 {
			ch |= imageSCNMemWrite
		}
	}
	if f&SecDiscard != 0 {
		ch |= imageSCNMemDiscardable
	}
	return ch
}

func alignUp64(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}

func alignUp32(v, a uint32) uint32 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}