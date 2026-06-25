package macho

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// In types.go (or a new file, e.g. nlist.go)
type nlist64Entry struct {
    strx  uint32
    ntype uint8
    nsect uint8
    ndesc uint16
    value uint64
}

// ── Public entry point ────────────────────────────────────────────────────────

func emitMachO(req *emitRequest, arch Arch) ([]byte, error) {
	e := &emitter{req: req, arch: arch}
	return e.emit()
}

// ── Emitter ───────────────────────────────────────────────────────────────────

type emitter struct {
	req  *emitRequest
	arch Arch

	// classified sections
	textSecs []*MergedSection
	dataSecs []*MergedSection

	// segment ranges — filled by computeRanges
	textVMAddr, textVMSize     uint64
	textFileOff, textFileSize  uint64
	dataVMAddr, dataVMSize     uint64
	dataFileOff, dataFileSize  uint64
	linkEditFileOff            uint64
	linkEditVMAddr             uint64

	// LINKEDIT blobs — filled by buildLinkEdit
	rebaseBlob   []byte
	bindBlob     []byte
	exportBlob   []byte
	symBlob      []byte
	indirectBlob []byte
	strBlob      []byte

	// symbol table metadata
	symbols  []nlist64Entry
	nLocals  uint32
	nExtDef  uint32
	nUndef   uint32
	indirectSyms []uint32
	stubsIST uint32
	gotIST   uint32

	// LINKEDIT offsets — filled by computeLinkEditOffsets
	rebaseOff   uint64
	bindOff     uint64
	exportOff   uint64
	symOff      uint64
	indirectOff uint64
	strOff      uint64
	codeSignOff uint64
	codeSignSize uint64
	linkEditSize uint64
}

func (e *emitter) emit() ([]byte, error) {
	// Step 1: classify sections into text / data buckets
	e.classifySections()

	// Step 2: compute segment VA and file ranges
	e.computeRanges()

	// Step 3: build all LINKEDIT blobs
	e.buildLinkEdit()

	// Step 4: compute exact LINKEDIT offsets now that blob sizes are known
	e.computeLinkEditOffsets()

	// Step 5: build load commands with correct offsets
	lc, err := e.buildLCs()
	if err != nil {
		return nil, err
	}

	// Step 6: check header + LCs fit in first page
	if machHeaderSize64+len(lc) > int(layoutPageSize) {
		return nil, fmt.Errorf("macho: header+load commands (%d) exceed page size",
			machHeaderSize64+len(lc))
	}

	// Step 7: serialize everything into the final buffer
	return e.serialize(lc), nil
}

// ── Step 1: classify ──────────────────────────────────────────────────────────

func (e *emitter) classifySections() {
	for _, ms := range e.req.Layout.Sections {
		if ms.Flags&SecAlloc == 0 {
			continue // non-alloc sections not emitted
		}
		if ms.Flags&SecWrite != 0 {
			e.dataSecs = append(e.dataSecs, ms)
		} else {
			e.textSecs = append(e.textSecs, ms)
		}
	}
}

// ── Step 2: compute segment ranges ───────────────────────────────────────────

func (e *emitter) computeRanges() {
	isExec := e.req.OutputType != OutputShared

	if len(e.textSecs) > 0 {
		if isExec {
			e.textVMAddr = 0x100000000
		} else {
			e.textVMAddr = e.textSecs[0].VAddr &^ (layoutPageSize - 1)
		}
		last := e.textSecs[len(e.textSecs)-1]
		e.textFileOff = 0
		e.textFileSize = last.FileOffset + last.Size
		e.textVMSize = last.VAddr + last.Size - e.textVMAddr
	}

	if len(e.dataSecs) > 0 {
		first := e.dataSecs[0]
		e.dataVMAddr = first.VAddr
		e.dataFileOff = first.FileOffset
		var lastVM, lastFile uint64
		for _, ms := range e.dataSecs {
			if end := ms.VAddr + ms.Size; end > lastVM {
				lastVM = end
			}
			if ms.Flags&SecBSS == 0 {
				if end := ms.FileOffset + ms.Size; end > lastFile {
					lastFile = end
				}
			}
		}
		e.dataVMSize = lastVM - e.dataVMAddr
		if lastFile > e.dataFileOff {
			e.dataFileSize = lastFile - e.dataFileOff
		}
	}

	var afterFile, afterVM uint64
	if len(e.dataSecs) > 0 {
		afterFile = e.dataFileOff + e.dataFileSize
		afterVM = e.dataVMAddr + e.dataVMSize
	} else if len(e.textSecs) > 0 {
		afterFile = e.textFileSize
		afterVM = e.textVMAddr + e.textVMSize
	}
	e.linkEditFileOff = alignUp64(afterFile, layoutPageSize)
	e.linkEditVMAddr = alignUp64(afterVM, layoutPageSize)
}

// ── Step 3: build LINKEDIT blobs ──────────────────────────────────────────────

func (e *emitter) buildLinkEdit() {
	e.rebaseBlob = []byte{REBASE_OPCODE_DONE}
	e.buildBind()
	e.buildExport()
	e.buildSymbols()
	e.buildIndirect()
}

func (e *emitter) buildBind() {
	req := e.req
	if len(req.PLTSyms) == 0 {
		e.bindBlob = []byte{BIND_OPCODE_DONE}
		return
	}
	gotSec, _ := req.Layout.SectionByName(sectionGOT)
	if gotSec == nil {
		e.bindBlob = []byte{BIND_OPCODE_DONE}
		return
	}
	segIdx := uint32(2) // PAGEZERO=0, TEXT=1, DATA=2
	if req.OutputType == OutputShared {
		segIdx = 1
	}
	e.bindBlob = BuildBindInfo(req.PLTSyms, gotSec, segIdx, req.Needed, req)
}

func (e *emitter) buildExport() {
	if e.req.OutputType == OutputShared {
		exports := make(map[string]uint64)
		for _, sym := range e.req.Symtab.All() {
			if sym.IsDefined() && sym.RawSym != nil &&
				sym.RawSym.Binding == BindGlobal && sym.VAddr != 0 {
				exports[sym.Name] = sym.VAddr
			}
		}
		e.exportBlob = BuildExportTrieForSymbols(exports)
	} else {
		e.exportBlob = BuildExportTrie()
	}
}

func (e *emitter) buildSymbols() {
	var strtab []byte
	strtab = append(strtab, 0) // null sentinel

	addStr := func(name string) uint32 {
		off := uint32(len(strtab))
		strtab = append(strtab, name...)
		strtab = append(strtab, 0)
		return off
	}

	// build section number map (1-based)
	sectNum := make(map[string]uint8)
	idx := uint8(1)
	for _, ms := range e.textSecs {
		sectNum[ms.Name] = idx
		idx++
	}
	for _, ms := range e.dataSecs {
		sectNum[ms.Name] = idx
		idx++
	}

	type si struct {
		sym   *TableSymbol
		ntype uint8
		nsect uint8
		ndesc uint16
		value uint64
	}

	var locals, extdefs, undefs []si

	for _, sym := range e.req.Symtab.All() {
		if sym.RawSym == nil && !sym.IsShared() {
			continue
		}
		switch {
		case sym.IsDefined():
			ns := sectNum[sym.RawSym.SectionName]
			if sym.RawSym.Binding == BindLocal {
				locals = append(locals, si{sym, N_SECT, ns, 0, sym.VAddr})
			} else {
				extdefs = append(extdefs, si{sym, N_SECT | N_EXT, ns, 0, sym.VAddr})
			}
		case sym.IsShared():
			ndesc := uint16(REFERENCE_FLAG_UNDEFINED_NON_LAZY)
			if sym.Weak {
				ndesc |= N_WEAK_REF
			}
			undefs = append(undefs, si{sym, N_UNDF | N_EXT, NO_SECT, ndesc, 0})
		}
	}

	sort.Slice(extdefs, func(i, j int) bool { return extdefs[i].sym.Name < extdefs[j].sym.Name })
	sort.Slice(undefs, func(i, j int) bool { return undefs[i].sym.Name < undefs[j].sym.Name })

	e.nLocals = uint32(len(locals))
	e.nExtDef = uint32(len(extdefs))
	e.nUndef = uint32(len(undefs))

	all := append(append(locals, extdefs...), undefs...)
	e.symbols = make([]nlist64Entry, len(all))
	for i, s := range all {
		e.symbols[i] = nlist64Entry{
			strx:  addStr(s.sym.Name),
			ntype: s.ntype,
			nsect: s.nsect,
			ndesc: s.ndesc,
			value: s.value,
		}
	}

	// encode nlist blob
	e.symBlob = make([]byte, len(e.symbols)*nlist64Size)
	for i, n := range e.symbols {
		off := i * nlist64Size
		binary.LittleEndian.PutUint32(e.symBlob[off:], n.strx)
		e.symBlob[off+4] = n.ntype
		e.symBlob[off+5] = n.nsect
		binary.LittleEndian.PutUint16(e.symBlob[off+6:], n.ndesc)
		binary.LittleEndian.PutUint64(e.symBlob[off+8:], n.value)
	}
	e.strBlob = strtab
}

func (e *emitter) buildIndirect() {
	if len(e.req.PLTSyms) == 0 {
		return
	}
	symIdx := make(map[string]uint32, len(e.symbols))
	for i, n := range e.symbols {
		symIdx[e.strName(n.strx)] = uint32(i)
	}
	e.stubsIST = uint32(len(e.indirectSyms))
	for _, name := range e.req.PLTSyms {
		if idx, ok := symIdx[name]; ok {
			e.indirectSyms = append(e.indirectSyms, idx)
		} else {
			e.indirectSyms = append(e.indirectSyms, 0x80000000)
		}
	}
	e.gotIST = uint32(len(e.indirectSyms))
	for _, name := range e.req.PLTSyms {
		if idx, ok := symIdx[name]; ok {
			e.indirectSyms = append(e.indirectSyms, idx)
		} else {
			e.indirectSyms = append(e.indirectSyms, 0x80000000)
		}
	}
	e.indirectBlob = make([]byte, len(e.indirectSyms)*4)
	for i, v := range e.indirectSyms {
		binary.LittleEndian.PutUint32(e.indirectBlob[i*4:], v)
	}
}

func (e *emitter) strName(strx uint32) string {
	if int(strx) >= len(e.strBlob) {
		return ""
	}
	end := int(strx)
	for end < len(e.strBlob) && e.strBlob[end] != 0 {
		end++
	}
	return string(e.strBlob[strx:end])
}

// ── Step 4: compute LINKEDIT offsets ─────────────────────────────────────────

func (e *emitter) computeLinkEditOffsets() {
	off := e.linkEditFileOff
	e.rebaseOff = off; off += uint64(len(e.rebaseBlob))
	e.bindOff   = off; off += uint64(len(e.bindBlob))
	e.exportOff = off; off += uint64(len(e.exportBlob))
	e.symOff    = off; off += uint64(len(e.symBlob))
	e.indirectOff = off; off += uint64(len(e.indirectBlob))
	e.strOff    = off; off += uint64(len(e.strBlob))

	// code signature — always last, 16-byte aligned
	isExec := e.req.OutputType != OutputShared
	if isExec {
		off = alignUp64(off, 16)
		e.codeSignOff = off
		nPages := (off + 0xFFF) >> 12
		// SuperBlob(20) + BlobIndex(8) + CodeDirectory(88) + identifier(6) + hashes
		e.codeSignSize = alignUp64(20+8+88+6+nPages*32, 8)
		off += e.codeSignSize
	}

	e.linkEditSize = off - e.linkEditFileOff
}

// ── Step 5: build load commands ───────────────────────────────────────────────

func (e *emitter) buildLCs() ([]byte, error) {
	req := e.req
	isExec := req.OutputType != OutputShared
	var lc []byte

	// ── segments ─────────────────────────────────────────────────────────────

	if isExec {
		lc = appendSeg64(lc, "__PAGEZERO", 0, 0x100000000, 0, 0,
			VM_PROT_NONE, VM_PROT_NONE, nil)
	}

	// __TEXT
	{
		var sects []secHdr
		for _, ms := range e.textSecs {
			seg, sect := machoSectionName(ms.Name, ms.Flags)
			st, sa := sectionTypeAttr(ms)
			r1, r2 := uint32(0), uint32(0)
			if ms.Name == sectionStubs {
				r1 = e.stubsIST
				r2 = uint32(stubEntrySize(e.arch))
			}
			sects = append(sects, secHdr{
				sect: sect, seg: seg,
				addr: ms.VAddr, size: ms.Size,
				off: uint32(ms.FileOffset), align: alignLog2(ms.Align),
				flags: st | sa, r1: r1, r2: r2,
			})
		}
		lc = appendSeg64(lc, "__TEXT",
			e.textVMAddr, e.textVMSize,
			e.textFileOff, e.textFileSize,
			VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE,
			VM_PROT_READ|VM_PROT_EXECUTE,
			sects)
	}

	// __DATA
	if len(e.dataSecs) > 0 {
		var sects []secHdr
		for _, ms := range e.dataSecs {
			seg, sect := machoSectionName(ms.Name, ms.Flags)
			st, sa := sectionTypeAttr(ms)
			r1 := uint32(0)
			if ms.Name == sectionGOT {
				r1 = e.gotIST
			}
			foff := uint32(ms.FileOffset)
			if ms.Flags&SecBSS != 0 {
				foff = 0
			}
			sects = append(sects, secHdr{
				sect: sect, seg: seg,
				addr: ms.VAddr, size: ms.Size,
				off: foff, align: alignLog2(ms.Align),
				flags: st | sa, r1: r1,
			})
		}
		p := VM_PROT_READ | VM_PROT_WRITE
		lc = appendSeg64(lc, "__DATA",
			e.dataVMAddr, e.dataVMSize,
			e.dataFileOff, e.dataFileSize,
			p, p, sects)
	}

	// __LINKEDIT
	lc = appendSeg64(lc, "__LINKEDIT",
		e.linkEditVMAddr, e.linkEditSize,
		e.linkEditFileOff, e.linkEditSize,
		VM_PROT_READ, VM_PROT_READ, nil)

	// ── non-segment load commands (order matches working Go binary) ───────────

	// LC_BUILD_VERSION
	lc = appendBuildVer(lc)

	// LC_MAIN (exec only)
	if isExec {
		var entryOff uint64
		if sym := req.Symtab.Lookup(req.Entry); sym != nil {
			entryOff = (sym.VAddr - e.textVMAddr) + e.textFileOff
		}
		lc = appendMain(lc, entryOff)
	}

	// LC_DYLD_INFO_ONLY
	lc = appendDyldInfo(lc,
		e.rebaseOff, len(e.rebaseBlob),
		e.bindOff, len(e.bindBlob),
		e.exportOff, len(e.exportBlob))

	// LC_SYMTAB
	lc = appendSymtab(lc,
		uint32(e.symOff), uint32(len(e.symbols)),
		uint32(e.strOff), uint32(len(e.strBlob)))

	// LC_DYSYMTAB
	lc = appendDysymtab(lc, e.nLocals, e.nExtDef, e.nUndef,
		uint32(e.indirectOff), uint32(len(e.indirectSyms)))

	// LC_LOAD_DYLINKER
	lc = appendDylinker(lc, "/usr/lib/dyld")

	// LC_LOAD_DYLIB entries
	for _, dep := range req.Needed {
		lc = appendDylib(lc, findInstallPath(dep))
	}

	// LC_UUID
	lc = appendUUID(lc)

	// LC_CODE_SIGNATURE (exec only, always last)
	if isExec {
		lc = appendCodeSig(lc, uint32(e.codeSignOff), uint32(e.codeSignSize))
	} else {
		soname := req.Soname
		if soname == "" {
			soname = "libunnamed.dylib"
		}
		lc = appendIDDylib(lc, soname)
	}

	if req.Rpath != "" {
		lc = appendRpath(lc, req.Rpath)
	}

	return lc, nil
}

// ── Step 6: serialize ─────────────────────────────────────────────────────────

func (e *emitter) serialize(lc []byte) []byte {
	ncmds, sizeofcmds := countLCs(lc)

	isExec := e.req.OutputType != OutputShared

	var filetype, flags uint32
	switch e.req.OutputType {
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
	switch e.arch {
	case ArchAMD64:
		cputype, cpusubtype = CPU_TYPE_AMD64, CPU_SUBTYPE_AMD64_ALL
	case ArchARM64:
		cputype, cpusubtype = CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL
	}

	totalSize := e.linkEditFileOff +
		uint64(len(e.rebaseBlob)) +
		uint64(len(e.bindBlob)) +
		uint64(len(e.exportBlob)) +
		uint64(len(e.symBlob)) +
		uint64(len(e.indirectBlob)) +
		uint64(len(e.strBlob))
	if isExec {
		totalSize = e.codeSignOff + e.codeSignSize
	}

	out := make([]byte, totalSize)

	// mach_header_64
	le := binary.LittleEndian
	le.PutUint32(out[0:],  MH_MAGIC_64)
	le.PutUint32(out[4:],  uint32(cputype))
	le.PutUint32(out[8:],  uint32(cpusubtype))
	le.PutUint32(out[12:], filetype)
	le.PutUint32(out[16:], ncmds)
	le.PutUint32(out[20:], sizeofcmds)
	le.PutUint32(out[24:], flags)
	// out[28:32] reserved = 0

	// load commands
	copy(out[machHeaderSize64:], lc)

	// section data
	for _, ms := range e.textSecs {
		if ms.Flags&SecBSS == 0 && len(ms.Data) > 0 {
			copy(out[ms.FileOffset:], ms.Data)
		}
	}
	for _, ms := range e.dataSecs {
		if ms.Flags&SecBSS == 0 && len(ms.Data) > 0 {
			copy(out[ms.FileOffset:], ms.Data)
		}
	}

	// LINKEDIT blobs
	fo := e.linkEditFileOff
	copy(out[fo:], e.rebaseBlob);   fo += uint64(len(e.rebaseBlob))
	copy(out[fo:], e.bindBlob);     fo += uint64(len(e.bindBlob))
	copy(out[fo:], e.exportBlob);   fo += uint64(len(e.exportBlob))
	copy(out[fo:], e.symBlob);      fo += uint64(len(e.symBlob))
	copy(out[fo:], e.indirectBlob); fo += uint64(len(e.indirectBlob))
	copy(out[fo:], e.strBlob)

	// ad-hoc code signature — computed over all bytes before this slot
	if isExec && e.codeSignSize > 0 {
		sig := buildAdHocSig(out[:e.codeSignOff], e.textFileSize)
		copy(out[e.codeSignOff:], sig)
	}

	return out
}

// ── LC writers ────────────────────────────────────────────────────────────────

type secHdr struct {
	sect, seg    string
	addr, size   uint64
	off, align   uint32
	reloff       uint32
	nreloc       uint32
	flags        uint32
	r1, r2       uint32
}

func appendSeg64(buf []byte, name string,
	vmaddr, vmsize, fileoff, filesize uint64,
	maxprot, initprot int32,
	sects []secHdr) []byte {

	nsects := uint32(len(sects))
	cmdsize := uint32(segCmdSize64) + nsects*uint32(sectSize64)
	buf = u32(buf, LC_SEGMENT_64)
	buf = u32(buf, cmdsize)
	buf = fixstr(buf, name, 16)
	buf = u64(buf, vmaddr)
	buf = u64(buf, vmsize)
	buf = u64(buf, fileoff)
	buf = u64(buf, filesize)
	buf = i32(buf, maxprot)
	buf = i32(buf, initprot)
	buf = u32(buf, nsects)
	buf = u32(buf, 0) // flags

	for _, s := range sects {
		buf = fixstr(buf, s.sect, 16)
		buf = fixstr(buf, s.seg, 16)
		buf = u64(buf, s.addr)
		buf = u64(buf, s.size)
		buf = u32(buf, s.off)
		buf = u32(buf, s.align)
		buf = u32(buf, s.reloff)
		buf = u32(buf, s.nreloc)
		buf = u32(buf, s.flags)
		buf = u32(buf, s.r1)
		buf = u32(buf, s.r2)
		buf = u32(buf, 0) // reserved3
	}
	return buf
}

func appendBuildVer(buf []byte) []byte {
	buf = u32(buf, LC_BUILD_VERSION)
	buf = u32(buf, uint32(buildVersionCmdSize))
	buf = u32(buf, PLATFORM_MACOS)
	buf = u32(buf, 0x000C0000) // macOS 12.0
	buf = u32(buf, 0x000C0000) // SDK 12.0
	buf = u32(buf, 0)          // ntools
	return buf
}

func appendMain(buf []byte, entryOff uint64) []byte {
	buf = u32(buf, LC_MAIN)
	buf = u32(buf, uint32(entryPointCmdSize))
	buf = u64(buf, entryOff)
	buf = u64(buf, 0) // stacksize
	return buf
}

func appendDyldInfo(buf []byte,
	rebOff uint64, rebSz int,
	bindOff uint64, bindSz int,
	expOff uint64, expSz int) []byte {
	buf = u32(buf, LC_DYLD_INFO_ONLY)
	buf = u32(buf, uint32(dyldInfoCmdSize))
	buf = u32(buf, uint32(rebOff));  buf = u32(buf, uint32(rebSz))
	buf = u32(buf, uint32(bindOff)); buf = u32(buf, uint32(bindSz))
	buf = u32(buf, 0);               buf = u32(buf, 0) // weak
	buf = u32(buf, 0);               buf = u32(buf, 0) // lazy
	buf = u32(buf, uint32(expOff));  buf = u32(buf, uint32(expSz))
	return buf
}

func appendSymtab(buf []byte, symoff, nsyms, stroff, strsize uint32) []byte {
	buf = u32(buf, LC_SYMTAB)
	buf = u32(buf, uint32(symtabCmdSize))
	buf = u32(buf, symoff)
	buf = u32(buf, nsyms)
	buf = u32(buf, stroff)
	buf = u32(buf, strsize)
	return buf
}

func appendDysymtab(buf []byte, nlocal, nextdef, nundef, indoff, nind uint32) []byte {
	buf = u32(buf, LC_DYSYMTAB)
	buf = u32(buf, uint32(dysymtabCmdSize))
	buf = u32(buf, 0);              buf = u32(buf, nlocal)
	buf = u32(buf, nlocal);         buf = u32(buf, nextdef)
	buf = u32(buf, nlocal+nextdef); buf = u32(buf, nundef)
	for i := 0; i < 8; i++ {
		buf = u32(buf, 0)
	}
	buf = u32(buf, indoff); buf = u32(buf, nind)
	buf = u32(buf, 0);      buf = u32(buf, 0)
	buf = u32(buf, 0);      buf = u32(buf, 0)
	return buf
}

func appendDylinker(buf []byte, path string) []byte {
	b := append([]byte(path), 0)
	total := align8(dylinkerCmdMinSize + len(b))
	buf = u32(buf, LC_LOAD_DYLINKER)
	buf = u32(buf, uint32(total))
	buf = u32(buf, uint32(dylinkerCmdMinSize))
	buf = append(buf, b...)
	return pad8(buf)
}

func appendDylib(buf []byte, path string) []byte {
	return dylibCmd(buf, LC_LOAD_DYLIB, path)
}

func appendIDDylib(buf []byte, path string) []byte {
	return dylibCmd(buf, LC_ID_DYLIB, path)
}

func dylibCmd(buf []byte, cmd uint32, name string) []byte {
	b := append([]byte(name), 0)
	total := align8(dylibCmdMinSize + len(b))
	buf = u32(buf, cmd)
	buf = u32(buf, uint32(total))
	buf = u32(buf, uint32(dylibCmdMinSize))
	buf = u32(buf, 0)          // timestamp
	buf = u32(buf, 0x00010000) // current_version
	buf = u32(buf, 0x00010000) // compatibility_version
	buf = append(buf, b...)
	return pad8(buf)
}

func appendUUID(buf []byte) []byte {
	buf = u32(buf, LC_UUID)
	buf = u32(buf, uint32(uuidCmdSize))
	return append(buf, make([]byte, 16)...)
}

func appendCodeSig(buf []byte, off, size uint32) []byte {
	buf = u32(buf, LC_CODE_SIGNATURE)
	buf = u32(buf, 16)
	buf = u32(buf, off)
	buf = u32(buf, size)
	return buf
}

func appendRpath(buf []byte, path string) []byte {
	b := append([]byte(path), 0)
	total := align8(rpathCmdMinSize + len(b))
	buf = u32(buf, LC_RPATH)
	buf = u32(buf, uint32(total))
	buf = u32(buf, uint32(rpathCmdMinSize))
	buf = append(buf, b...)
	return pad8(buf)
}

// ── countLCs ──────────────────────────────────────────────────────────────────

func countLCs(lc []byte) (ncmds, sizeofcmds uint32) {
	pos := 0
	for pos+8 <= len(lc) {
		sz := binary.LittleEndian.Uint32(lc[pos+4:])
		if sz < 8 {
			break
		}
		ncmds++
		sizeofcmds += sz
		pos += int(sz)
	}
	return
}

// ── ad-hoc code signature ─────────────────────────────────────────────────────

func buildAdHocSig(data []byte, execSegFileSize uint64) []byte {
	const (
		magic    = uint32(0xFADE0CC0)
		cdMagic  = uint32(0xFADE0C02)
		cdVer    = uint32(0x20400)
		flagAdhoc = uint32(0x2)
		pageSize = 4096
		sha256Sz = 32
	)

	ident := []byte("a.out\x00")
	nPages := (len(data) + pageSize - 1) / pageSize

	const fixedHdr = 88
	identOff := uint32(fixedHdr)
	hashOff  := uint32(fixedHdr + len(ident))
	cdSize   := uint32(fixedHdr + len(ident) + nPages*sha256Sz)

	cd := make([]byte, cdSize)
	be := binary.BigEndian
	be.PutUint32(cd[0:],  cdMagic)
	be.PutUint32(cd[4:],  cdSize)
	be.PutUint32(cd[8:],  cdVer)
	be.PutUint32(cd[12:], flagAdhoc)
	be.PutUint32(cd[16:], hashOff)
	be.PutUint32(cd[20:], identOff)
	be.PutUint32(cd[24:], 0)             // nSpecialSlots
	be.PutUint32(cd[28:], uint32(nPages))
	be.PutUint32(cd[32:], uint32(len(data))) // codeLimit
	cd[36] = sha256Sz
	cd[37] = 2  // SHA256
	cd[38] = 0  // platform
	cd[39] = 12 // pageSize log2
	be.PutUint32(cd[40:], 0) // spare2
	be.PutUint32(cd[44:], 0) // scatterOffset
	be.PutUint32(cd[48:], 0) // teamOffset
	be.PutUint32(cd[52:], 0) // spare3
	be.PutUint64(cd[56:], 0) // codeLimit64
	be.PutUint64(cd[64:], 0) // execSegBase
	be.PutUint64(cd[72:], execSegFileSize)
	be.PutUint64(cd[80:], 1) // execSegFlags: CS_EXECSEG_MAIN_BINARY

	copy(cd[identOff:], ident)

	page := make([]byte, pageSize)
	for i := 0; i < nPages; i++ {
		start := i * pageSize
		end := start + pageSize
		clear(page)
		if end > len(data) {
			end = len(data)
		}
		copy(page, data[start:end])
		h := sha256.Sum256(page)
		copy(cd[int(hashOff)+i*sha256Sz:], h[:])
	}

	// SuperBlob
	const superHdr = 12
	const idxSz   = 8
	superSize := uint32(superHdr + idxSz + len(cd))
	super := make([]byte, superSize)
	be.PutUint32(super[0:], magic)
	be.PutUint32(super[4:], superSize)
	be.PutUint32(super[8:], 1) // count
	be.PutUint32(super[12:], 0) // slot: CSSLOT_CODEDIRECTORY
	be.PutUint32(super[16:], uint32(superHdr+idxSz))
	copy(super[superHdr+idxSz:], cd)
	return super
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func u32(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
func u64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}
func i32(buf []byte, v int32) []byte { return u32(buf, uint32(v)) }
func fixstr(buf []byte, s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return append(buf, b...)
}
func align8(n int) int        { return (n + 7) &^ 7 }
func pad8(buf []byte) []byte {
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	return buf
}
func alignUp64(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
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

func machoSectionName(name string, flags SectionFlags) (seg, sect string) {
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

func sectionTypeAttr(ms *MergedSection) (stype, sattr uint32) {
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

const REFERENCE_FLAG_UNDEFINED_NON_LAZY = uint16(0)