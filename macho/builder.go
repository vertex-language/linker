package macho

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"crypto/sha256"
)

func emitMachO(req *emitRequest, arch Arch) ([]byte, error) {
	b := &machoEmitter{req: req, arch: arch}
	return b.emit()
}

// ── Section name helpers ──────────────────────────────────────────────────────

func machoNames(name string, flags SectionFlags) (seg, sect string) {
	if idx := strings.IndexByte(name, '/'); idx >= 0 {
		return name[:idx], name[idx+1:]
	}
	switch {
	case name == ".text" || strings.HasPrefix(name, ".text."):
		return "__TEXT", "__text"
	case name == ".plt" || name == ".plt.got":
		return "__TEXT", "__stubs"
	case name == ".rodata" || strings.HasPrefix(name, ".rodata"):
		return "__TEXT", "__const"
	case name == ".eh_frame":
		return "__TEXT", "__eh_frame"
	case name == ".gcc_except_table":
		return "__TEXT", "__gcc_except_tab"
	case name == ".data" || strings.HasPrefix(name, ".data."):
		return "__DATA", "__data"
	case name == ".bss" || strings.HasPrefix(name, ".bss."):
		return "__DATA", "__bss"
	case name == ".got" || name == ".got.plt":
		return "__DATA", "__got"
	case name == ".tdata":
		return "__DATA", "__thread_data"
	case name == ".tbss":
		return "__DATA", "__thread_bss"
	default:
		if flags&SecWrite != 0 {
			return "__DATA", "__" + strings.TrimPrefix(name, ".")
		}
		return "__TEXT", "__" + strings.TrimPrefix(name, ".")
	}
}

// ── Emitter ───────────────────────────────────────────────────────────────────

type machoEmitter struct {
	req  *emitRequest
	arch Arch

	textSecs     []*MergedSection
	dataSecs     []*MergedSection
	nonAllocSecs []*MergedSection

	textSegVMAddr, textSegVMSize    uint64
	textSegFileOff, textSegFileSize uint64
	dataSegVMAddr, dataSegVMSize    uint64
	dataSegFileOff, dataSegFileSize uint64
	linkeditFileOff, linkeditVMAddr uint64

	rebaseBlob   []byte
	bindBlob     []byte
	exportBlob   []byte
	symtabBlob   []byte
	strtabBlob   []byte
	indirectBlob []byte

	symbols      []nlist64Entry
	strtab       []byte
	nLocals      uint32
	nExtDef      uint32
	nUndef       uint32
	indirectSyms []uint32

	stubsIST uint32
	gotIST   uint32
	nPLT     int

	codeSignOff  uint64
	codeSignSize uint64
}

type nlist64Entry struct {
	strx  uint32
	ntype uint8
	nsect uint8
	ndesc uint16
	value uint64
}

func (b *machoEmitter) emit() ([]byte, error) {
	b.strtab = []byte{'\x00'}

	if err := b.classifySections(); err != nil {
		return nil, err
	}
	b.computeSegmentRanges()
	b.buildLinkedit()

	lcBytes, err := b.buildLoadCommands()
	if err != nil {
		return nil, err
	}

	hdrTotal := machHeaderSize64 + len(lcBytes)
	if hdrTotal > int(layoutPageSize) {
		return nil, fmt.Errorf("macho: header + load commands (%d bytes) exceed page size (0x%x)",
			hdrTotal, layoutPageSize)
	}

	return b.serialize(lcBytes), nil
}

func (b *machoEmitter) classifySections() error {
	for _, ms := range b.req.Layout.Sections {
		if ms.Flags&SecAlloc == 0 {
			b.nonAllocSecs = append(b.nonAllocSecs, ms)
		} else if ms.Flags&SecWrite != 0 {
			b.dataSecs = append(b.dataSecs, ms)
		} else {
			b.textSecs = append(b.textSecs, ms)
		}
	}
	return nil
}

func (b *machoEmitter) computeSegmentRanges() {
	isExec := b.req.OutputType != OutputShared

	if len(b.textSecs) > 0 {
		last := b.textSecs[len(b.textSecs)-1]
		if isExec {
			b.textSegVMAddr = 0x100000000
		} else {
			b.textSegVMAddr = b.textSecs[0].VAddr &^ (layoutPageSize - 1)
		}
		b.textSegFileOff = 0
		b.textSegFileSize = last.FileOffset + last.Size
		b.textSegVMSize = last.VAddr + last.Size - b.textSegVMAddr
	}

	if len(b.dataSecs) > 0 {
		first := b.dataSecs[0]
		b.dataSegVMAddr = first.VAddr
		b.dataSegFileOff = first.FileOffset

		var lastFileEnd, lastVMEnd uint64
		for _, sec := range b.dataSecs {
			if vmEnd := sec.VAddr + sec.Size; vmEnd > lastVMEnd {
				lastVMEnd = vmEnd
			}
			if sec.Flags&SecBSS == 0 {
				if fe := sec.FileOffset + sec.Size; fe > lastFileEnd {
					lastFileEnd = fe
				}
			}
		}
		if lastFileEnd > b.dataSegFileOff {
			b.dataSegFileSize = lastFileEnd - b.dataSegFileOff
		}
		b.dataSegVMSize = lastVMEnd - b.dataSegVMAddr
	}

	var afterFileOff, afterVMAddr uint64
	if len(b.dataSecs) > 0 {
		afterFileOff = b.dataSegFileOff + b.dataSegFileSize
		afterVMAddr = b.dataSegVMAddr + b.dataSegVMSize
	} else if len(b.textSecs) > 0 {
		afterFileOff = b.textSegFileSize
		afterVMAddr = b.textSegVMAddr + b.textSegVMSize
	}
	b.linkeditFileOff = alignUp64(afterFileOff, layoutPageSize)
	b.linkeditVMAddr = alignUp64(afterVMAddr, layoutPageSize)
}

func alignUp64(v, align uint64) uint64 {
	if align <= 1 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// ── LINKEDIT construction ─────────────────────────────────────────────────────

func (b *machoEmitter) buildLinkedit() {
	b.rebaseBlob = BuildRebaseInfo()
	b.buildBindBlob()
	b.buildExportBlob()
	b.buildSymbolTable()
	b.buildIndirectSymTable()
}

func (b *machoEmitter) buildBindBlob() {
	req := b.req
	if len(req.PLTSyms) == 0 {
		b.bindBlob = []byte{BIND_OPCODE_DONE}
		return
	}
	gotSec, _ := req.Layout.SectionByName(sectionGOT)
	if gotSec == nil {
		b.bindBlob = []byte{BIND_OPCODE_DONE}
		return
	}
	dataSegIdx := uint32(2) // PAGEZERO=0, TEXT=1, DATA=2 for executables
	if req.OutputType == OutputShared {
		dataSegIdx = 1 // TEXT=0, DATA=1 for dylibs
	}
	b.bindBlob = BuildBindInfo(req.PLTSyms, gotSec, dataSegIdx, req.Needed, req)
}

func (b *machoEmitter) buildExportBlob() {
	if b.req.OutputType == OutputShared {
		exports := make(map[string]uint64)
		for _, sym := range b.req.Symtab.All() {
			if sym.IsDefined() && sym.RawSym != nil &&
				sym.RawSym.Binding == BindGlobal && sym.VAddr != 0 {
				exports[sym.Name] = sym.VAddr
			}
		}
		b.exportBlob = BuildExportTrieForSymbols(exports)
	} else {
		b.exportBlob = BuildExportTrie()
	}
}

func (b *machoEmitter) buildSymbolTable() {
	strtabAdd := func(name string) uint32 {
		off := uint32(len(b.strtab))
		b.strtab = append(b.strtab, []byte(name)...)
		b.strtab = append(b.strtab, 0)
		return off
	}

	// Build 1-based Mach-O section number map.
	sectNum := make(map[string]uint8)
	i := uint8(1)
	for _, ms := range b.textSecs {
		sectNum[ms.Name] = i
		i++
	}
	for _, ms := range b.dataSecs {
		sectNum[ms.Name] = i
		i++
	}

	type symInfo struct {
		sym   *TableSymbol
		ntype uint8
		nsect uint8
		ndesc uint16
		value uint64
	}

	var locals, extDef, undefs []symInfo

	for _, sym := range b.req.Symtab.All() {
		if sym.RawSym == nil && !sym.IsShared() {
			continue
		}
		switch {
		case sym.IsDefined():
			raw := sym.RawSym
			ns := sectNum[raw.SectionName]
			if raw.Binding == BindLocal {
				locals = append(locals, symInfo{sym: sym, ntype: N_SECT, nsect: ns, value: sym.VAddr})
			} else {
				extDef = append(extDef, symInfo{sym: sym, ntype: N_SECT | N_EXT, nsect: ns, value: sym.VAddr})
			}
		case sym.IsShared():
			ndesc := uint16(REFERENCE_FLAG_UNDEFINED_NON_LAZY)
			if sym.Weak {
				ndesc |= N_WEAK_REF
			}
			undefs = append(undefs, symInfo{sym: sym, ntype: N_UNDF | N_EXT, nsect: NO_SECT, ndesc: ndesc})
		}
	}

	sort.Slice(extDef, func(i, j int) bool { return extDef[i].sym.Name < extDef[j].sym.Name })
	sort.Slice(undefs, func(i, j int) bool { return undefs[i].sym.Name < undefs[j].sym.Name })

	b.nLocals = uint32(len(locals))
	b.nExtDef = uint32(len(extDef))
	b.nUndef = uint32(len(undefs))

	allSyms := append(append(locals, extDef...), undefs...)
	b.symbols = make([]nlist64Entry, len(allSyms))
	for idx, si := range allSyms {
		b.symbols[idx] = nlist64Entry{
			strx:  strtabAdd(si.sym.Name),
			ntype: si.ntype,
			nsect: si.nsect,
			ndesc: si.ndesc,
			value: si.value,
		}
	}

	b.symtabBlob = make([]byte, len(b.symbols)*nlist64Size)
	for i, e := range b.symbols {
		off := i * nlist64Size
		binary.LittleEndian.PutUint32(b.symtabBlob[off:], e.strx)
		b.symtabBlob[off+4] = e.ntype
		b.symtabBlob[off+5] = e.nsect
		binary.LittleEndian.PutUint16(b.symtabBlob[off+6:], e.ndesc)
		binary.LittleEndian.PutUint64(b.symtabBlob[off+8:], e.value)
	}
	b.strtabBlob = b.strtab
}

func (b *machoEmitter) buildIndirectSymTable() {
	if len(b.req.PLTSyms) == 0 {
		return
	}

	symIdx := make(map[string]uint32, len(b.symbols))
	for i, e := range b.symbols {
		symIdx[b.symbolName(e.strx)] = uint32(i)
	}

	b.stubsIST = uint32(len(b.indirectSyms))
	for _, name := range b.req.PLTSyms {
		if idx, ok := symIdx[name]; ok {
			b.indirectSyms = append(b.indirectSyms, idx)
		} else {
			b.indirectSyms = append(b.indirectSyms, 0x80000000)
		}
	}

	b.gotIST = uint32(len(b.indirectSyms))
	for _, name := range b.req.PLTSyms {
		if idx, ok := symIdx[name]; ok {
			b.indirectSyms = append(b.indirectSyms, idx)
		} else {
			b.indirectSyms = append(b.indirectSyms, 0x80000000)
		}
	}
	b.nPLT = len(b.req.PLTSyms)

	b.indirectBlob = make([]byte, len(b.indirectSyms)*4)
	for i, v := range b.indirectSyms {
		binary.LittleEndian.PutUint32(b.indirectBlob[i*4:], v)
	}
}

func (b *machoEmitter) symbolName(strx uint32) string {
	if int(strx) >= len(b.strtabBlob) {
		return ""
	}
	end := int(strx)
	for end < len(b.strtabBlob) && b.strtabBlob[end] != 0 {
		end++
	}
	return string(b.strtabBlob[strx:end])
}

// ── Load command construction ─────────────────────────────────────────────────

func (b *machoEmitter) buildLoadCommands() ([]byte, error) {
	req := b.req
	isExec := req.OutputType != OutputShared

	off := b.linkeditFileOff
	rebaseOff := off; off += uint64(len(b.rebaseBlob))
	bindOff   := off; off += uint64(len(b.bindBlob))
	exportOff := off; off += uint64(len(b.exportBlob))
	symOff    := off; off += uint64(len(b.symtabBlob))
	indirectOff := off; off += uint64(len(b.indirectBlob))
	strtabOff := off; off += uint64(len(b.strtabBlob))

	// Reserve space for the code signature at the end of __LINKEDIT.
	// codeLimit = everything before the signature; nPages drives hash count.
	// We align to 16 bytes as codesign requires.
	if isExec {
		off = alignUp64(off, 16)
		b.codeSignOff = off
		nPages := (off + 0xFFF) >> 12
		// SuperBlob(20) + CodeDirectory header(88) + identifier(6) + hashes
		b.codeSignSize = alignUp64(20+88+6+nPages*32, 8)
		off += b.codeSignSize
	}

	linkeditSize := off - b.linkeditFileOff

	w := newLCWriter()

	if isExec {
		w.seg64("__PAGEZERO", 0, 0x100000000, 0, 0, VM_PROT_NONE, VM_PROT_NONE, nil)
	}

	// __TEXT
	{
		var sects []sectionHdr
		for _, ms := range b.textSecs {
			seg, sect := machoNames(ms.Name, ms.Flags)
			stype, sattr := machoSectionTypeAttr(ms)
			reserved1, reserved2 := uint32(0), uint32(0)
			if ms.Name == sectionStubs {
				reserved1 = b.stubsIST
				reserved2 = uint32(stubEntrySize(b.arch))
			}
			sects = append(sects, sectionHdr{
				sectname: sect, segname: seg,
				addr: ms.VAddr, size: ms.Size,
				offset:    uint32(ms.FileOffset),
				align:     alignLog2(ms.Align),
				flags:     stype | sattr,
				reserved1: reserved1,
				reserved2: reserved2,
			})
		}
		w.seg64("__TEXT", b.textSegVMAddr, b.textSegVMSize,
			b.textSegFileOff, b.textSegFileSize,
			VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE,
			VM_PROT_READ|VM_PROT_EXECUTE,
			sects)
	}

	// __DATA
	if len(b.dataSecs) > 0 {
		var sects []sectionHdr
		for _, ms := range b.dataSecs {
			seg, sect := machoNames(ms.Name, ms.Flags)
			stype, sattr := machoSectionTypeAttr(ms)
			reserved1 := uint32(0)
			if ms.Name == sectionGOT {
				reserved1 = b.gotIST
			}
			fileOff := uint32(ms.FileOffset)
			if ms.Flags&SecBSS != 0 {
				fileOff = 0
			}
			sects = append(sects, sectionHdr{
				sectname: sect, segname: seg,
				addr: ms.VAddr, size: ms.Size,
				offset:    fileOff,
				align:     alignLog2(ms.Align),
				flags:     stype | sattr,
				reserved1: reserved1,
			})
		}
		dataProt := VM_PROT_READ | VM_PROT_WRITE
		w.seg64("__DATA", b.dataSegVMAddr, b.dataSegVMSize,
			b.dataSegFileOff, b.dataSegFileSize, dataProt, dataProt, sects)
	}

	// __LINKEDIT — vmsize now covers the code signature too
	w.seg64("__LINKEDIT", b.linkeditVMAddr, linkeditSize,
		b.linkeditFileOff, linkeditSize, VM_PROT_READ, VM_PROT_READ, nil)

	lc := w.bytes()

	lc = appendDyldInfo(lc, rebaseOff, len(b.rebaseBlob),
		bindOff, len(b.bindBlob), exportOff, len(b.exportBlob))

	lc = appendSymtab(lc, uint32(symOff), uint32(len(b.symbols)),
		uint32(strtabOff), uint32(len(b.strtabBlob)))

	lc = appendDysymtab(lc, b.nLocals, b.nExtDef, b.nUndef,
		uint32(indirectOff), uint32(len(b.indirectSyms)))

	lc = appendLoadDylinker(lc, "/usr/lib/dyld")
	lc = appendUUID(lc)
	lc = appendBuildVersion(lc)
	lc = appendSourceVersion(lc)

	if isExec {
		var entryOff uint64
		if sym := req.Symtab.Lookup(req.Entry); sym != nil {
			// entryOff is a FILE offset into __TEXT, not a VA-relative value.
			// Formula: (symVA - textSegVMAddr) + textSegFileOff
			entryOff = (sym.VAddr - b.textSegVMAddr) + b.textSegFileOff
		}
		lc = appendMain(lc, entryOff)

		// LC_CODE_SIGNATURE must be last — codesign expects it at the end.
		lc = appendCodeSignature(lc, uint32(b.codeSignOff), uint32(b.codeSignSize))
	} else {
		soname := req.Soname
		if soname == "" {
			soname = "libunnamed.dylib"
		}
		lc = appendIDDylib(lc, soname)
	}

	for _, depName := range req.Needed {
		lc = appendLoadDylib(lc, findInstallPath(depName))
	}
	if req.Rpath != "" {
		lc = appendRpath(lc, req.Rpath)
	}

	return lc, nil
}

// ── Load command byte builders ────────────────────────────────────────────────

type lcWriter struct{ buf []byte }

func newLCWriter() *lcWriter     { return &lcWriter{} }
func (w *lcWriter) bytes() []byte { return w.buf }

type sectionHdr struct {
	sectname  string
	segname   string
	addr      uint64
	size      uint64
	offset    uint32
	align     uint32
	reloff    uint32
	nreloc    uint32
	flags     uint32
	reserved1 uint32
	reserved2 uint32
}

func (w *lcWriter) seg64(segname string, vmaddr, vmsize, fileoff, filesize uint64,
	maxprot, initprot int32, sects []sectionHdr) {

	nsects := uint32(len(sects))
	cmdsize := uint32(segCmdSize64) + nsects*uint32(sectSize64)
	w.buf = appendU32(w.buf, LC_SEGMENT_64)
	w.buf = appendU32(w.buf, cmdsize)
	w.buf = appendFixedStr(w.buf, segname, 16)
	w.buf = appendU64(w.buf, vmaddr)
	w.buf = appendU64(w.buf, vmsize)
	w.buf = appendU64(w.buf, fileoff)
	w.buf = appendU64(w.buf, filesize)
	w.buf = appendI32(w.buf, maxprot)
	w.buf = appendI32(w.buf, initprot)
	w.buf = appendU32(w.buf, nsects)
	w.buf = appendU32(w.buf, 0)

	for _, s := range sects {
		w.buf = appendFixedStr(w.buf, s.sectname, 16)
		w.buf = appendFixedStr(w.buf, s.segname, 16)
		w.buf = appendU64(w.buf, s.addr)
		w.buf = appendU64(w.buf, s.size)
		w.buf = appendU32(w.buf, s.offset)
		w.buf = appendU32(w.buf, s.align)
		w.buf = appendU32(w.buf, s.reloff)
		w.buf = appendU32(w.buf, s.nreloc)
		w.buf = appendU32(w.buf, s.flags)
		w.buf = appendU32(w.buf, s.reserved1)
		w.buf = appendU32(w.buf, s.reserved2)
		w.buf = appendU32(w.buf, 0) // reserved3
	}
}

func appendDyldInfo(buf []byte, rebaseOff uint64, rebSz int, bindOff uint64, bindSz int, exportOff uint64, expSz int) []byte {
	buf = appendU32(buf, LC_DYLD_INFO_ONLY)
	buf = appendU32(buf, uint32(dyldInfoCmdSize))
	buf = appendU32(buf, uint32(rebaseOff))
	buf = appendU32(buf, uint32(rebSz))
	buf = appendU32(buf, uint32(bindOff))
	buf = appendU32(buf, uint32(bindSz))
	buf = appendU32(buf, 0) // weak bind
	buf = appendU32(buf, 0)
	buf = appendU32(buf, 0) // lazy bind
	buf = appendU32(buf, 0)
	buf = appendU32(buf, uint32(exportOff))
	buf = appendU32(buf, uint32(expSz))
	return buf
}

func appendSymtab(buf []byte, symoff, nsyms, stroff, strsize uint32) []byte {
	buf = appendU32(buf, LC_SYMTAB)
	buf = appendU32(buf, uint32(symtabCmdSize))
	buf = appendU32(buf, symoff)
	buf = appendU32(buf, nsyms)
	buf = appendU32(buf, stroff)
	buf = appendU32(buf, strsize)
	return buf
}

func appendDysymtab(buf []byte, nlocals, nextdef, nundef, indirectOff, nindirect uint32) []byte {
	buf = appendU32(buf, LC_DYSYMTAB)
	buf = appendU32(buf, uint32(dysymtabCmdSize))
	buf = appendU32(buf, 0)
	buf = appendU32(buf, nlocals)
	buf = appendU32(buf, nlocals)
	buf = appendU32(buf, nextdef)
	buf = appendU32(buf, nlocals+nextdef)
	buf = appendU32(buf, nundef)
	for i := 0; i < 8; i++ {
		buf = appendU32(buf, 0)
	}
	buf = appendU32(buf, indirectOff)
	buf = appendU32(buf, nindirect)
	buf = appendU32(buf, 0)
	buf = appendU32(buf, 0)
	buf = appendU32(buf, 0)
	buf = appendU32(buf, 0)
	return buf
}

func appendLoadDylinker(buf []byte, path string) []byte {
	nameOff := uint32(dylinkerCmdMinSize)
	nameBytes := append([]byte(path), 0)
	total := (int(dylinkerCmdMinSize) + len(nameBytes) + 7) &^ 7
	buf = appendU32(buf, LC_LOAD_DYLINKER)
	buf = appendU32(buf, uint32(total))
	buf = appendU32(buf, nameOff)
	buf = append(buf, nameBytes...)
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func appendUUID(buf []byte) []byte {
	buf = appendU32(buf, LC_UUID)
	buf = appendU32(buf, uint32(uuidCmdSize))
	return append(buf, make([]byte, 16)...)
}

func appendBuildVersion(buf []byte) []byte {
	buf = appendU32(buf, LC_BUILD_VERSION)
	buf = appendU32(buf, uint32(buildVersionCmdSize))
	buf = appendU32(buf, PLATFORM_MACOS)
	buf = appendU32(buf, 0x000C0000)
	buf = appendU32(buf, 0x000C0000)
	buf = appendU32(buf, 0)
	return buf
}

func appendSourceVersion(buf []byte) []byte {
	buf = appendU32(buf, LC_SOURCE_VERSION)
	buf = appendU32(buf, uint32(sourceVersionCmdSize))
	return appendU64(buf, 0)
}

func appendMain(buf []byte, entryOff uint64) []byte {
	buf = appendU32(buf, LC_MAIN)
	buf = appendU32(buf, uint32(entryPointCmdSize))
	buf = appendU64(buf, entryOff)
	return appendU64(buf, 0)
}

func appendIDDylib(buf []byte, name string) []byte {
	return appendDylibCmd(buf, LC_ID_DYLIB, name)
}

func appendLoadDylib(buf []byte, path string) []byte {
	return appendDylibCmd(buf, LC_LOAD_DYLIB, path)
}

func appendDylibCmd(buf []byte, cmd uint32, name string) []byte {
	nameOff := uint32(dylibCmdMinSize)
	nameBytes := append([]byte(name), 0)
	total := (int(dylibCmdMinSize) + len(nameBytes) + 7) &^ 7
	buf = appendU32(buf, cmd)
	buf = appendU32(buf, uint32(total))
	buf = appendU32(buf, nameOff)
	buf = appendU32(buf, 0)
	buf = appendU32(buf, 0x00010000)
	buf = appendU32(buf, 0x00010000)
	buf = append(buf, nameBytes...)
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func appendRpath(buf []byte, path string) []byte {
	pathOff := uint32(rpathCmdMinSize)
	pathBytes := append([]byte(path), 0)
	total := (int(rpathCmdMinSize) + len(pathBytes) + 7) &^ 7
	buf = appendU32(buf, LC_RPATH)
	buf = appendU32(buf, uint32(total))
	buf = appendU32(buf, pathOff)
	buf = append(buf, pathBytes...)
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

// ── Serialization ─────────────────────────────────────────────────────────────

func (b *machoEmitter) serialize(lcBytes []byte) []byte {
	ncmds, sizeofcmds := countLCs(lcBytes)

	var filetype, flags uint32
	switch b.req.OutputType {
	case OutputExec:
		filetype = MH_EXECUTE
		flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL
	case OutputPIE:
		filetype = MH_EXECUTE
		flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE
	case OutputShared:
		filetype = MH_DYLIB
		flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL
	}

	var cputype, cpusubtype int32
	switch b.arch {
	case ArchAMD64:
		cputype, cpusubtype = CPU_TYPE_AMD64, CPU_SUBTYPE_AMD64_ALL
	case ArchARM64:
		cputype, cpusubtype = CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL
	}

	totalSize := b.linkeditFileOff +
		uint64(len(b.rebaseBlob)) +
		uint64(len(b.bindBlob)) +
		uint64(len(b.exportBlob)) +
		uint64(len(b.symtabBlob)) +
		uint64(len(b.indirectBlob)) +
		uint64(len(b.strtabBlob))

	// Include the reserved code-signature slot.
	if b.codeSignSize > 0 {
		totalSize = b.codeSignOff + b.codeSignSize
	}

	out := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(out[0:],  MH_MAGIC_64)
	binary.LittleEndian.PutUint32(out[4:],  uint32(cputype))
	binary.LittleEndian.PutUint32(out[8:],  uint32(cpusubtype))
	binary.LittleEndian.PutUint32(out[12:], filetype)
	binary.LittleEndian.PutUint32(out[16:], ncmds)
	binary.LittleEndian.PutUint32(out[20:], sizeofcmds)
	binary.LittleEndian.PutUint32(out[24:], flags)

	copy(out[machHeaderSize64:], lcBytes)

	for _, ms := range b.textSecs {
		if ms.Flags&SecBSS == 0 && len(ms.Data) > 0 {
			copy(out[ms.FileOffset:], ms.Data)
		}
	}
	for _, ms := range b.dataSecs {
		if ms.Flags&SecBSS == 0 && len(ms.Data) > 0 {
			copy(out[ms.FileOffset:], ms.Data)
		}
	}

	fo := b.linkeditFileOff
	copy(out[fo:], b.rebaseBlob);   fo += uint64(len(b.rebaseBlob))
	copy(out[fo:], b.bindBlob);     fo += uint64(len(b.bindBlob))
	copy(out[fo:], b.exportBlob);   fo += uint64(len(b.exportBlob))
	copy(out[fo:], b.symtabBlob);   fo += uint64(len(b.symtabBlob))
	copy(out[fo:], b.indirectBlob); fo += uint64(len(b.indirectBlob))
	copy(out[fo:], b.strtabBlob)

	// Compute the ad-hoc code signature over all bytes up to codeSignOff,
	// then write it into the reserved slot. Must be last.
	if b.codeSignSize > 0 {
		sig := buildAdHocCodeSignature(out[:b.codeSignOff], b.textSegFileSize)
		copy(out[b.codeSignOff:], sig)
	}

	return out
}

func appendCodeSignature(buf []byte, dataOff, dataSize uint32) []byte {
	buf = appendU32(buf, LC_CODE_SIGNATURE)
	buf = appendU32(buf, 16) // cmdsize: cmd(4) + cmdsize(4) + dataoff(4) + datasize(4)
	buf = appendU32(buf, dataOff)
	buf = appendU32(buf, dataSize)
	return buf
}

// ── Binary encoding helpers ───────────────────────────────────────────────────

func appendU32(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
func appendU64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}
func appendI32(buf []byte, v int32) []byte { return appendU32(buf, uint32(v)) }
func appendFixedStr(buf []byte, s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return append(buf, b...)
}

func countLCs(lcBytes []byte) (ncmds, sizeofcmds uint32) {
	pos := 0
	for pos+8 <= len(lcBytes) {
		cmdsize := binary.LittleEndian.Uint32(lcBytes[pos+4:])
		if cmdsize < 8 {
			break
		}
		ncmds++
		sizeofcmds += cmdsize // ← was: return uint32(len(lcBytes))
		pos += int(cmdsize)
	}
	return ncmds, sizeofcmds
}

func machoSectionTypeAttr(ms *MergedSection) (stype, sattr uint32) {
	switch ms.Name {
	case sectionStubs:
		return S_SYMBOL_STUBS, S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
	case sectionGOT:
		return S_NON_LAZY_SYMBOL_POINTERS, 0
	}
	if ms.Flags&SecBSS != 0 {
		return S_ZEROFILL, 0
	}
	if ms.Flags&SecExec != 0 {
		return S_REGULAR, S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
	}
	return S_REGULAR, 0
}

func alignLog2(align uint64) uint32 {
	if align <= 1 {
		return 0
	}
	n := uint32(0)
	for align > 1 {
		align >>= 1
		n++
	}
	return n
}

func findInstallPath(soname string) string {
	known := map[string]string{
		"libSystem.B.dylib": "/usr/lib/libSystem.B.dylib",
		"libc.dylib":        "/usr/lib/libc.dylib",
		"libpthread.dylib":  "/usr/lib/libpthread.dylib",
		"libm.dylib":        "/usr/lib/libm.dylib",
		"libobjc.A.dylib":   "/usr/lib/libobjc.A.dylib",
		"libdyld.dylib":     "/usr/lib/system/libdyld.dylib",
		"libc++.1.dylib":    "/usr/lib/libc++.1.dylib",
	}
	if path, ok := known[soname]; ok {
		return path
	}
	return "/usr/lib/" + soname
}

// buildAdHocCodeSignature produces a minimal ad-hoc SuperBlob + CodeDirectory
// that satisfies macOS arm64's signature requirement without a developer cert.
// data is the binary content up to (not including) the signature slot.
// execSegFileSize is the filesize of the __TEXT segment (b.textSegFileSize).
//
// Note: code-signing structures are big-endian regardless of the host arch.
func buildAdHocCodeSignature(data []byte, execSegFileSize uint64) []byte {
	const (
		csmagicEmbeddedSignature = uint32(0xFADE0CC0)
		csmagicCodeDirectory     = uint32(0xFADE0C02)
		cdVersion                = uint32(0x20400) // supports execSeg fields
		cdFlagAdhoc              = uint32(0x00000002)
		csSlotCodeDirectory      = uint32(0)
		hashTypeSHA256           = uint8(2)
		sha256Len                = 32
		pageBytes                = 4096
		pageSizeLog2             = uint8(12)
	)

	identifier := []byte("a.out\x00")

	nPages := (len(data) + pageBytes - 1) / pageBytes

	// CodeDirectory layout:
	//   88-byte fixed header  (version 0x20400)
	//   identifier bytes
	//   nPages × 32-byte SHA-256 hashes
	const cdFixedHdrSize = 88
	identOffset := uint32(cdFixedHdrSize)
	hashOffset  := uint32(cdFixedHdrSize + len(identifier))
	cdSize      := uint32(cdFixedHdrSize + len(identifier) + nPages*sha256Len)

	cd := make([]byte, cdSize)
	be := binary.BigEndian
	be.PutUint32(cd[0:],  csmagicCodeDirectory)
	be.PutUint32(cd[4:],  cdSize)
	be.PutUint32(cd[8:],  cdVersion)
	be.PutUint32(cd[12:], cdFlagAdhoc)
	be.PutUint32(cd[16:], hashOffset)  // offset of first code hash within CD
	be.PutUint32(cd[20:], identOffset) // offset of identifier string within CD
	be.PutUint32(cd[24:], 0)           // nSpecialSlots
	be.PutUint32(cd[28:], uint32(nPages))
	be.PutUint32(cd[32:], uint32(len(data))) // codeLimit: byte count to hash
	cd[36] = sha256Len    // hashSize
	cd[37] = hashTypeSHA256
	cd[38] = 0            // platform (0 = no platform)
	cd[39] = pageSizeLog2
	be.PutUint32(cd[40:], 0) // spare2
	be.PutUint32(cd[44:], 0) // scatterOffset  (v2.1)
	be.PutUint32(cd[48:], 0) // teamOffset     (v2.2)
	be.PutUint32(cd[52:], 0) // spare3         (v2.3)
	be.PutUint64(cd[56:], 0) // codeLimit64    (v2.3)
	be.PutUint64(cd[64:], 0) // execSegBase    (v2.4) — file offset of __TEXT
	be.PutUint64(cd[72:], execSegFileSize) // execSegLimit (v2.4)
	be.PutUint64(cd[80:], 1) // execSegFlags   (v2.4) — CS_EXECSEG_MAIN_BINARY

	copy(cd[identOffset:], identifier)

	// Hash each 4 KiB page; the final page is zero-padded.
	page := make([]byte, pageBytes)
	for i := 0; i < nPages; i++ {
		start := i * pageBytes
		end := start + pageBytes
		if end > len(data) {
			// Clear reused buffer tail so padding is deterministic.
			clear(page[len(data)-start:])
			end = len(data)
		}
		copy(page, data[start:end])
		h := sha256.Sum256(page)
		copy(cd[int(hashOffset)+i*sha256Len:], h[:])
	}

	// SuperBlob: magic(4) + length(4) + count(4) + BlobIndex[type(4)+offset(4)] + CD
	const superHdrSize = 12
	const blobIdxSize  = 8
	superSize := uint32(superHdrSize + blobIdxSize + len(cd))

	super := make([]byte, superSize)
	be.PutUint32(super[0:], csmagicEmbeddedSignature)
	be.PutUint32(super[4:], superSize)
	be.PutUint32(super[8:], 1) // one blob
	// BlobIndex[0]: CSSLOT_CODEDIRECTORY at offset 20 (right after this index)
	be.PutUint32(super[12:], csSlotCodeDirectory)
	be.PutUint32(super[16:], uint32(superHdrSize+blobIdxSize))
	copy(super[superHdrSize+blobIdxSize:], cd)

	return super
}

const REFERENCE_FLAG_UNDEFINED_NON_LAZY = uint16(0)