// builder.go — ELF64 binary serialiser.
package elf

import (
	"bytes"
	"fmt"
)

const (
	elfHeaderSize = 64
	phdrEntrySize = 56
	shdrEntrySize = 64
)

// Section describes an ELF section to be included in the output binary.
type Section struct {
	Name    string
	Type    uint32
	Flags   uint64
	Data    []byte
	Align   uint64
	Size    uint64
	Link    uint32
	Info    uint32
	EntSize uint64
	PreassignedAddr       uint64
	PreassignedFileOffset uint64
}

// Symbol describes a .symtab entry.
type Symbol struct {
	Name    string
	Section string
	Offset  uint64
	Size    uint64
	Global  bool
	Weak    bool
	Type    uint8
	Vis     uint8
}

// Segment describes a custom PT_* program header.
type Segment struct {
	Type     uint32
	Flags    uint32
	Align    uint64
	Sections []string
}

// Builder accumulates sections, symbols, and dynamic-linking config, then
// serialises them into a valid ELF64 binary via Emit.
type Builder struct {
	arch     uint16
	fileType uint16
	flags    uint32
	entry    string

	sections      []Section
	symbols       []Symbol
	extraSegments []Segment

	interp  string
	needed  []string
	soname  string
	rpath   string
	dynSyms []string
}

// NewBuilder creates an ELF64 builder for arch.
func NewBuilder(arch uint16) *Builder {
	return &Builder{arch: arch, fileType: ET_EXEC}
}

func (b *Builder) SetShared()             { b.fileType = ET_DYN }
func (b *Builder) SetFlags(f uint32)      { b.flags = f }
func (b *Builder) SetInterp(path string)  { b.interp = path }
func (b *Builder) AddNeeded(lib string)   { b.needed = append(b.needed, lib) }
func (b *Builder) SetSoname(name string)  { b.soname = name }
func (b *Builder) SetRpath(path string)   { b.rpath = path }
func (b *Builder) AddSection(s Section)  { b.sections = append(b.sections, s) }
func (b *Builder) AddSymbol(s Symbol)    { b.symbols = append(b.symbols, s) }
func (b *Builder) SetEntry(name string)  { b.entry = name }
func (b *Builder) AddSegment(s Segment)  { b.extraSegments = append(b.extraSegments, s) }
func (b *Builder) AddDynSym(name string) { b.dynSyms = append(b.dynSyms, name) }

// Emit serialises and returns the ELF64 binary bytes.
func (b *Builder) Emit() ([]byte, error) {
	em := &emitter{b: b}
	em.secByName = make(map[string]*builtSection)
	em.symAddr = make(map[string]uint64)
	return em.emit()
}

// Emit is the top-level entry point called by Link.
// It translates an EmitRequest into a fully serialised ELF64 binary.
func Emit(req *EmitRequest) ([]byte, error) {
	b := NewBuilder(req.Arch)

	if req.OutputType != OutputExec {
		b.SetShared()
	}
	if req.Arch == ArchRISCV64 {
		b.SetFlags(EF_RISCV_RVC | EF_RISCV_FLOAT_ABI_DOUBLE)
	}
	if req.Interp != "" {
		b.SetInterp(req.Interp)
	}
	for _, n := range req.Needed {
		b.AddNeeded(n)
	}
	if req.Soname != "" {
		b.SetSoname(req.Soname)
	}
	if req.Rpath != "" {
		b.SetRpath(req.Rpath)
	}
	for _, name := range req.PLTSyms {
		b.AddDynSym(name)
	}
	if req.Entry != "" {
		b.SetEntry(req.Entry)
	}

	for _, ms := range req.Layout.Sections {
		sec := Section{
			Name:                  ms.Name,
			Type:                  ms.RawType,
			Flags:                 ms.RawFlags,
			Align:                 ms.Align,
			PreassignedAddr:       ms.VAddr,
			PreassignedFileOffset: ms.FileOffset,
		}
		if ms.Flags&SecBSS != 0 {
			sec.Type = SHT_NOBITS
			sec.Size = ms.Size
		} else {
			sec.Data = ms.Data
		}
		b.AddSection(sec)
	}

	for _, sym := range req.Symtab.All() {
		if sym.RawSym == nil {
			continue
		}
		raw := sym.RawSym
		var secName string
		var offset uint64
		switch raw.SectionName {
		case "*ABS*":
			secName = "*ABS*"
			offset = raw.Value
		case "":
			secName = ""
		default:
			secName = raw.SectionName
			if ms, ok := req.Layout.SectionByName(raw.SectionName); ok && sym.VAddr >= ms.VAddr {
				offset = sym.VAddr - ms.VAddr
			}
		}
		b.AddSymbol(Symbol{
			Name:    sym.Name,
			Section: secName,
			Offset:  offset,
			Size:    raw.Size,
			Global:  raw.Binding == BindGlobal,
			Weak:    raw.Binding == BindWeak,
			Type:    uint8(raw.Type),
			Vis:     raw.Vis,
		})
	}

	return b.Emit()
}

// ── internal emitter ──────────────────────────────────────────────────────────

type builtSection struct {
	name    string
	shType  uint32
	flags   uint64
	data    []byte
	memSize uint64
	align   uint64
	link    uint32
	info    uint32
	entSize uint64
	fileOff uint64
	addr    uint64
	shIdx   int

	hasPreassigned        bool
	preassignedAddr       uint64
	preassignedFileOffset uint64
}

type emitter struct {
	b         *Builder
	secs      []*builtSection
	secByName map[string]*builtSection
	shstrtab  strTab
	strtab    strTab
	symAddr   map[string]uint64
}

func (e *emitter) addSec(sec *builtSection) {
	sec.shIdx = len(e.secs)
	e.secs = append(e.secs, sec)
	if sec.name != "" {
		e.secByName[sec.name] = sec
	}
}

func (e *emitter) emit() ([]byte, error) {
	e.addSec(&builtSection{shType: SHT_NULL, align: 1})

	for _, s := range e.b.sections {
		align := s.Align
		if align == 0 {
			align = 1
		}
		memSz := uint64(len(s.Data))
		if s.Type == SHT_NOBITS && s.Size > memSz {
			memSz = s.Size
		}
		bs := &builtSection{
			name:    s.Name,
			shType:  s.Type,
			flags:   s.Flags,
			data:    s.Data,
			memSize: memSz,
			align:   align,
			link:    s.Link,
			info:    s.Info,
			entSize: s.EntSize,
		}
		if s.PreassignedAddr != 0 || s.PreassignedFileOffset != 0 {
			bs.hasPreassigned        = true
			bs.preassignedAddr       = s.PreassignedAddr
			bs.preassignedFileOffset = s.PreassignedFileOffset
		}
		e.addSec(bs)
	}

	hasDynamic := e.b.interp != "" || len(e.b.needed) > 0 ||
		e.b.soname != "" || e.b.rpath != "" || e.b.fileType == ET_DYN
	var dynSec *builtSection
	if hasDynamic {
		if e.b.interp != "" {
			interpData := append([]byte(e.b.interp), 0)
			e.addSec(&builtSection{
				name:    ".interp",
				shType:  SHT_PROGBITS,
				flags:   SHF_ALLOC,
				data:    interpData,
				memSize: uint64(len(interpData)),
				align:   1,
			})
		}
		// .dynstr must be added before .dynamic so its shIdx is known
		// when we set dynSec.link below.
		e.addSec(&builtSection{name: ".dynstr", shType: SHT_STRTAB, flags: SHF_ALLOC, align: 1})
		e.addSec(&builtSection{
			name:    ".dynsym",
			shType:  SHT_DYNSYM,
			flags:   SHF_ALLOC,
			align:   8,
			entSize: symEntSize,
			info:    1,
		})
		dynSec = &builtSection{
			name:    ".dynamic",
			shType:  SHT_DYNAMIC,
			flags:   SHF_ALLOC | SHF_WRITE,
			align:   8,
			entSize: dynEntSize,
			// sh_link must point to .dynstr per the ELF spec (§5-11).
			link: uint32(e.secByName[".dynstr"].shIdx),
		}
		e.addSec(dynSec)
	}

	symtabSec := &builtSection{name: ".symtab", shType: SHT_SYMTAB, align: 8, entSize: symEntSize}
	strtabSec := &builtSection{name: ".strtab", shType: SHT_STRTAB, align: 1}
	shstrtabSec := &builtSection{name: ".shstrtab", shType: SHT_STRTAB, align: 1}
	e.addSec(symtabSec)
	e.addSec(strtabSec)
	e.addSec(shstrtabSec)

	e.shstrtab.add("")
	for _, sec := range e.secs {
		if sec.name != "" {
			e.shstrtab.add(sec.name)
		}
	}
	shstrtabSec.data = e.shstrtab.bytes()
	shstrtabSec.memSize = uint64(len(shstrtabSec.data))

	e.strtab.add("")
	var localSyms, globalSyms []Symbol
	for _, sym := range e.b.symbols {
		if sym.Weak || sym.Global {
			globalSyms = append(globalSyms, sym)
		} else {
			localSyms = append(localSyms, sym)
		}
	}
	firstGlobal := 1 + len(localSyms)

	var symBuf bytes.Buffer
	symBuf.Write(make([]byte, symEntSize))
	for _, sym := range append(localSyms, globalSyms...) {
		e.appendSym(&symBuf, sym)
	}
	symtabSec.data = symBuf.Bytes()
	symtabSec.memSize = uint64(len(symtabSec.data))
	symtabSec.link = uint32(strtabSec.shIdx)
	symtabSec.info = uint32(firstGlobal)
	strtabSec.data = e.strtab.bytes()
	strtabSec.memSize = uint64(len(strtabSec.data))

	if hasDynamic {
		e.buildDynamicSections(dynSec)
	}

	estimated := e.estimatePhdrs(hasDynamic)
	headerArea := uint64(elfHeaderSize) + uint64(estimated)*phdrEntrySize
	e.layoutSections(headerArea)

	for _, sym := range e.b.symbols {
		switch sym.Section {
		case "":
		case "*ABS*":
			e.symAddr[sym.Name] = sym.Offset
		default:
			if sec, ok := e.secByName[sym.Section]; ok {
				e.symAddr[sym.Name] = sec.addr + sym.Offset
			}
		}
	}

	symBuf.Reset()
	symBuf.Write(make([]byte, symEntSize))
	for _, sym := range append(localSyms, globalSyms...) {
		e.appendSym(&symBuf, sym)
	}
	symtabSec.data = symBuf.Bytes()
	symtabSec.memSize = uint64(len(symtabSec.data))
	e.layoutSections(headerArea)

	if hasDynamic {
		e.buildDynamicSections(dynSec)
	}

	var entryAddr uint64
	if e.b.entry != "" {
		addr, ok := e.symAddr[e.b.entry]
		if !ok {
			return nil, fmt.Errorf("elf: entry symbol %q not found", e.b.entry)
		}
		entryAddr = addr
	}

	phdrs := e.buildPhdrs(hasDynamic)
	if len(phdrs) != estimated {
		headerArea = uint64(elfHeaderSize) + uint64(len(phdrs))*phdrEntrySize
		e.layoutSections(headerArea)
		if hasDynamic {
			e.buildDynamicSections(dynSec)
		}
		phdrs = e.buildPhdrs(hasDynamic)
	}

	var maxFileOff uint64
	for _, sec := range e.secs {
		if sec.shType == SHT_NOBITS || sec.shType == SHT_NULL {
			continue
		}
		if end := sec.fileOff + uint64(len(sec.data)); end > maxFileOff {
			maxFileOff = end
		}
	}
	shoff := alignUp(maxFileOff, 8)

	fileSize := shoff + uint64(len(e.secs))*shdrEntrySize
	buf := make([]byte, fileSize)

	e.writeEhdr(buf, entryAddr, uint32(len(phdrs)), shoff, uint32(len(e.secs)), uint32(shstrtabSec.shIdx))
	for i, ph := range phdrs {
		e.writePhdr(buf[elfHeaderSize+i*phdrEntrySize:], ph)
	}
	for _, sec := range e.secs {
		if sec.shType == SHT_NULL || sec.shType == SHT_NOBITS || len(sec.data) == 0 {
			continue
		}
		copy(buf[sec.fileOff:], sec.data)
	}
	for i, sec := range e.secs {
		e.writeShdr(buf[int(shoff)+i*shdrEntrySize:], sec)
	}
	return buf, nil
}

func (e *emitter) layoutSections(headerArea uint64) {
	base := uint64(0)
	if e.b.fileType == ET_EXEC {
		base = 0x400000
	}
	offset := headerArea
	for _, sec := range e.secs {
		if sec.shType == SHT_NULL {
			sec.fileOff, sec.addr = 0, 0
			continue
		}
		if sec.hasPreassigned {
			sec.fileOff = sec.preassignedFileOffset
			sec.addr = sec.preassignedAddr
			if sec.shType != SHT_NOBITS && len(sec.data) > 0 {
				if end := sec.fileOff + uint64(len(sec.data)); end > offset {
					offset = end
				}
			}
			continue
		}
		if sec.shType == SHT_NOBITS {
			offset = alignUp(offset, sec.align)
			sec.fileOff = offset
			if sec.flags&SHF_ALLOC != 0 {
				sec.addr = base + offset
			}
			continue
		}
		dataLen := uint64(len(sec.data))
		if dataLen == 0 {
			sec.fileOff = offset
			if sec.flags&SHF_ALLOC != 0 {
				sec.addr = base + offset
			}
			continue
		}
		offset = alignUp(offset, sec.align)
		sec.fileOff = offset
		if sec.flags&SHF_ALLOC != 0 {
			sec.addr = base + offset
		}
		offset += dataLen
	}
}

func (e *emitter) appendSym(w *bytes.Buffer, sym Symbol) {
	nameIdx := e.strtab.add(sym.Name)
	var binding uint8
	switch {
	case sym.Weak:
		binding = STB_WEAK
	case sym.Global:
		binding = STB_GLOBAL
	default:
		binding = STB_LOCAL
	}
	stInfo := (binding << 4) | (sym.Type & 0x0F)

	var shndx uint16
	var value uint64
	switch sym.Section {
	case "":
		shndx = uint16(SHN_UNDEF)
	case "*ABS*":
		shndx = uint16(SHN_ABS)
		value = sym.Offset
	default:
		if sec, ok := e.secByName[sym.Section]; ok {
			shndx = uint16(sec.shIdx)
			value = sec.addr + sym.Offset
		}
	}
	if a, ok := e.symAddr[sym.Name]; ok {
		value = a
	}

	var b [symEntSize]byte
	putU32le(b[0:], nameIdx)
	b[4] = stInfo
	b[5] = sym.Vis & 0x03
	putU16le(b[6:], shndx)
	putU64le(b[8:], value)
	putU64le(b[16:], sym.Size)
	w.Write(b[:])
}

func (e *emitter) estimatePhdrs(hasDynamic bool) int {
	seen := make(map[uint32]bool)
	hasTLS := false
	for _, sec := range e.secs {
		if sec.flags&SHF_ALLOC != 0 && sec.shType != SHT_NULL {
			seen[segPermKey(sec.flags)] = true
		}
		if sec.flags&SHF_TLS != 0 {
			hasTLS = true
		}
	}
	n := len(seen) + 1 // +1 PT_PHDR
	if e.b.interp != "" {
		n++
	}
	if hasDynamic {
		n++
	}
	if hasTLS {
		n++
	}
	n++ // PT_GNU_STACK
	n += len(e.b.extraSegments)
	return n
}

type phdrDesc struct {
	pType  uint32
	flags  uint32
	off    uint64
	vaddr  uint64
	paddr  uint64
	filesz uint64
	memsz  uint64
	align  uint64
}

func (e *emitter) buildPhdrs(hasDynamic bool) []phdrDesc {
	var phs []phdrDesc
	base := uint64(0)
	if e.b.fileType == ET_EXEC {
		base = 0x400000
	}

	nPhdrs := e.estimatePhdrs(hasDynamic)
	phdrFileOff := uint64(elfHeaderSize)
	phdrFileSz := uint64(nPhdrs) * phdrEntrySize
	phs = append(phs, phdrDesc{
		pType: PT_PHDR, flags: PF_R,
		off: phdrFileOff, vaddr: base + phdrFileOff, paddr: base + phdrFileOff,
		filesz: phdrFileSz, memsz: phdrFileSz, align: 8,
	})

	if sec := e.secByName[".interp"]; sec != nil {
		sz := uint64(len(sec.data))
		phs = append(phs, phdrDesc{
			pType: PT_INTERP, flags: PF_R,
			off: sec.fileOff, vaddr: sec.addr, paddr: sec.addr,
			filesz: sz, memsz: sz, align: 1,
		})
	}

	firstLoad := true
	for _, perm := range []uint32{PF_R | PF_X, PF_R, PF_R | PF_W} {
		var group []*builtSection
		for _, sec := range e.secs {
			if sec.flags&SHF_ALLOC != 0 && sec.shType != SHT_NULL && segPermKey(sec.flags) == perm {
				group = append(group, sec)
			}
		}
		if len(group) == 0 {
			continue
		}
		first := group[0]
		var fileEnd, memEnd uint64
		for _, s := range group {
			if s.shType == SHT_NOBITS {
				if me := s.fileOff + s.memSize; me > memEnd {
					memEnd = me
				}
			} else {
				fe := s.fileOff + uint64(len(s.data))
				if fe > fileEnd {
					fileEnd = fe
				}
				if fe > memEnd {
					memEnd = fe
				}
			}
		}
		startOff, startAddr := first.fileOff, first.addr
		if firstLoad {
			startOff = 0
			startAddr = base
			firstLoad = false
		}
		phs = append(phs, phdrDesc{
			pType: PT_LOAD, flags: perm,
			off: startOff, vaddr: startAddr, paddr: startAddr,
			filesz: fileEnd - startOff, memsz: memEnd - startOff,
			align: 0x1000,
		})
	}

	if hasDynamic {
		if sec := e.secByName[".dynamic"]; sec != nil {
			sz := uint64(len(sec.data))
			phs = append(phs, phdrDesc{
				pType: PT_DYNAMIC, flags: PF_R | PF_W,
				off: sec.fileOff, vaddr: sec.addr, paddr: sec.addr,
				filesz: sz, memsz: sz, align: 8,
			})
		}
	}

	var tlsFirst *builtSection
	var tlsFilesz, tlsMemsz uint64
	for _, sec := range e.secs {
		if sec.flags&SHF_TLS == 0 || sec.shType == SHT_NULL {
			continue
		}
		if tlsFirst == nil {
			tlsFirst = sec
		}
		if rel := (sec.fileOff + sec.memSize) - tlsFirst.fileOff; rel > tlsMemsz {
			tlsMemsz = rel
		}
		if sec.shType != SHT_NOBITS {
			if frel := (sec.fileOff + uint64(len(sec.data))) - tlsFirst.fileOff; frel > tlsFilesz {
				tlsFilesz = frel
			}
		}
	}
	if tlsFirst != nil {
		phs = append(phs, phdrDesc{
			pType: PT_TLS, flags: PF_R,
			off: tlsFirst.fileOff, vaddr: tlsFirst.addr, paddr: tlsFirst.addr,
			filesz: tlsFilesz, memsz: tlsMemsz, align: tlsFirst.align,
		})
	}

	phs = append(phs, phdrDesc{pType: PT_GNU_STACK, flags: PF_R | PF_W, align: 0x1000})

	for _, seg := range e.b.extraSegments {
		if len(seg.Sections) == 0 {
			a := seg.Align
			if a == 0 {
				a = 1
			}
			phs = append(phs, phdrDesc{pType: seg.Type, flags: seg.Flags, align: a})
			continue
		}
		var first *builtSection
		var fileEnd, memEnd uint64
		for _, sname := range seg.Sections {
			sec := e.secByName[sname]
			if sec == nil {
				continue
			}
			if first == nil {
				first = sec
			}
			if sec.shType == SHT_NOBITS {
				if me := sec.fileOff + sec.memSize; me > memEnd {
					memEnd = me
				}
			} else {
				fe := sec.fileOff + uint64(len(sec.data))
				if fe > fileEnd {
					fileEnd = fe
				}
				if fe > memEnd {
					memEnd = fe
				}
			}
		}
		if first == nil {
			continue
		}
		a := seg.Align
		if a == 0 {
			a = 1
		}
		phs = append(phs, phdrDesc{
			pType: seg.Type, flags: seg.Flags,
			off: first.fileOff, vaddr: first.addr, paddr: first.addr,
			filesz: fileEnd - first.fileOff, memsz: memEnd - first.fileOff,
			align: a,
		})
	}
	return phs
}

func (e *emitter) writeEhdr(buf []byte, entry uint64, phnum uint32, shoff uint64, shnum, shstrndx uint32) {
	buf[EI_MAG0] = ELFMAG0
	buf[EI_MAG1] = ELFMAG1
	buf[EI_MAG2] = ELFMAG2
	buf[EI_MAG3] = ELFMAG3
	buf[EI_CLASS] = ELFCLASS64
	buf[EI_DATA] = ELFDATA2LSB
	buf[EI_VERSION] = EV_CURRENT
	buf[EI_OSABI] = ELFOSABI_NONE
	putU16le(buf[16:], e.b.fileType)
	putU16le(buf[18:], e.b.arch)
	putU32le(buf[20:], EV_CURRENT)
	putU64le(buf[24:], entry)
	putU64le(buf[32:], elfHeaderSize)
	putU64le(buf[40:], shoff)
	putU32le(buf[48:], e.b.flags)
	putU16le(buf[52:], elfHeaderSize)
	putU16le(buf[54:], phdrEntrySize)
	wPhnum := phnum
	if wPhnum >= uint32(PN_XNUM) {
		wPhnum = uint32(PN_XNUM)
	}
	wShnum := shnum
	if wShnum >= uint32(SHN_LORESERVE) {
		wShnum = 0
	}
	wShstrndx := shstrndx
	if wShstrndx >= uint32(SHN_LORESERVE) {
		wShstrndx = uint32(SHN_XINDEX)
	}
	putU16le(buf[56:], uint16(wPhnum))
	putU16le(buf[58:], shdrEntrySize)
	putU16le(buf[60:], uint16(wShnum))
	putU16le(buf[62:], uint16(wShstrndx))
}

func (e *emitter) writePhdr(buf []byte, ph phdrDesc) {
	putU32le(buf[0:], ph.pType)
	putU32le(buf[4:], ph.flags)
	putU64le(buf[8:], ph.off)
	putU64le(buf[16:], ph.vaddr)
	putU64le(buf[24:], ph.paddr)
	putU64le(buf[32:], ph.filesz)
	putU64le(buf[40:], ph.memsz)
	putU64le(buf[48:], ph.align)
}

func (e *emitter) writeShdr(buf []byte, sec *builtSection) {
	nameIdx := uint32(0)
	if sec.name != "" {
		nameIdx = e.shstrtab.index(sec.name)
	}
	a := sec.align
	if a == 0 {
		a = 1
	}
	sz := uint64(len(sec.data))
	if sec.shType == SHT_NOBITS {
		sz = sec.memSize
	}
	putU32le(buf[0:], nameIdx)
	putU32le(buf[4:], sec.shType)
	putU64le(buf[8:], sec.flags)
	putU64le(buf[16:], sec.addr)
	putU64le(buf[24:], sec.fileOff)
	putU64le(buf[32:], sz)
	putU32le(buf[40:], sec.link)
	putU32le(buf[44:], sec.info)
	putU64le(buf[48:], a)
	putU64le(buf[56:], sec.entSize)
}

// ── strTab ────────────────────────────────────────────────────────────────────

type strTab struct {
	data    []byte
	indices map[string]uint32
}

// add interns s and returns its byte offset within the table.
// The empty string is always at offset 0; callers must seed it with add("").
func (t *strTab) add(s string) uint32 {
	if t.indices == nil {
		t.indices = make(map[string]uint32)
	}
	if idx, ok := t.indices[s]; ok {
		return idx
	}
	idx := uint32(len(t.data))
	t.indices[s] = idx
	t.data = append(t.data, s...)
	t.data = append(t.data, 0) // NUL terminator
	return idx
}

// bytes returns the raw table contents for writing into the output section.
func (t *strTab) bytes() []byte { return t.data }

// index returns the previously recorded offset for s.
// Only call this after add(s); returns 0 (the null entry) if s is unknown.
func (t *strTab) index(s string) uint32 {
	if t.indices == nil {
		return 0
	}
	return t.indices[s]
}

// ── helpers ───────────────────────────────────────────────────────────────────

// segPermKey maps a section's sh_flags to the PT_LOAD permission group it
// belongs to.  Three groups are recognised: RX (code), RO (read-only data),
// and RW (writable data).
func segPermKey(flags uint64) uint32 {
	switch {
	case flags&SHF_EXECINSTR != 0:
		return PF_R | PF_X
	case flags&SHF_WRITE != 0:
		return PF_R | PF_W
	default:
		return PF_R
	}
}