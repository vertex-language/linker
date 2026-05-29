// dynamic.go — PLT/GOT synthesis and ELF dynamic-section builders.
package elf

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// ── Core PLT types and functions (formerly linker/dynamic.go) ─────────────────

const (
	pltHeaderSize = 16 // PLT0 stub size for AMD64; ARM64/RISCV64 use 32 bytes
	pltEntrySize  = 16 // per-symbol PLT stub size
	gotEntrySize  = 8  // GOT slot size (ELF64)
)

// PLTEntry pairs a shared symbol with its 0-based stub index (PLT0 not counted).
type PLTEntry struct {
	Name string
	Sym  *TableSymbol
	Idx  int
}

// PLTPatcher writes arch-specific PLT stubs and dynamic reloc entries.
type PLTPatcher interface {
	PatchPLT(plt, gotPLT, relaPLT []byte, pltBase, gotBase uint64, syms []PLTEntry)
}

// CollectPLTSymbols returns every kindShared symbol that is actually
// referenced by at least one object relocation, in stable first-seen order.
func CollectPLTSymbols(symtab *SymbolTable, objects []*Object) []PLTEntry {
	referenced := make(map[string]bool)
	for _, obj := range objects {
		for _, rel := range obj.Relocs {
			if int(rel.SymIdx) < len(obj.Symbols) && obj.Symbols[rel.SymIdx] != nil {
				if name := obj.Symbols[rel.SymIdx].Name; name != "" {
					referenced[name] = true
				}
			}
		}
	}

	var out []PLTEntry
	seen := make(map[string]bool)
	for _, obj := range objects {
		for _, raw := range obj.Symbols {
			if raw == nil || raw.Name == "" || seen[raw.Name] || !referenced[raw.Name] {
				continue
			}
			sym := symtab.Lookup(raw.Name)
			if sym == nil || !sym.IsShared() {
				continue
			}
			seen[raw.Name] = true
			out = append(out, PLTEntry{Name: raw.Name, Sym: sym, Idx: len(out)})
		}
	}
	return out
}

// InjectPLTSections appends placeholder .plt, .got.plt, and .rela.plt sections
// to layout so they receive virtual addresses during AssignLayout.
func InjectPLTSections(layout *Layout, syms []PLTEntry) {
	n := len(syms)
	plt := &MergedSection{
		Name:     ".plt",
		Flags:    SecAlloc | SecExec,
		RawType:  1, // SHT_PROGBITS
		RawFlags: 0x2 | 0x4,
		Data:     make([]byte, pltHeaderSize+n*pltEntrySize),
		Size:     uint64(pltHeaderSize + n*pltEntrySize),
		Align:    16,
	}
	gotPLT := &MergedSection{
		Name:     ".got.plt",
		Flags:    SecAlloc | SecWrite,
		RawType:  1,
		RawFlags: 0x2 | 0x1,
		Data:     make([]byte, (3+n)*gotEntrySize),
		Size:     uint64((3 + n) * gotEntrySize),
		Align:    8,
	}
	relaPLT := &MergedSection{
		Name:     ".rela.plt",
		Flags:    SecAlloc,
		RawType:  4, // SHT_RELA
		RawFlags: 0x2 | 0x40,
		Data:     make([]byte, n*relaEntrySize),
		Size:     uint64(n * relaEntrySize),
		Align:    8,
	}
	layout.Sections = append(layout.Sections, plt, gotPLT, relaPLT)
	layout.secByName[".plt"] = plt
	layout.secByName[".got.plt"] = gotPLT
	layout.secByName[".rela.plt"] = relaPLT
}

// PatchPLT fills PLT stubs, GOT.PLT initial values, and JUMP_SLOT reloc entries,
// then assigns each PLT symbol's VAddr to its stub so PatchAll targets it correctly.
func PatchPLT(pp PLTPatcher, layout *Layout, syms []PLTEntry) error {
	pltSec, ok1 := layout.SectionByName(".plt")
	gotSec, ok2 := layout.SectionByName(".got.plt")
	relaSec, ok3 := layout.SectionByName(".rela.plt")
	if !ok1 || !ok2 || !ok3 {
		return nil
	}
	pp.PatchPLT(pltSec.Data, gotSec.Data, relaSec.Data, pltSec.VAddr, gotSec.VAddr, syms)
	return nil
}

// putI32LE writes a signed little-endian 32-bit integer into b[0:4].
func putI32LE(b []byte, v int32) { binary.LittleEndian.PutUint32(b, uint32(v)) }

// ── ELF PLTPatcher ────────────────────────────────────────────────────────────

type elfPLTPatcher struct{ arch uint16 }

func (pp *elfPLTPatcher) PatchPLT(plt, gotPLT, relaPLT []byte, pltBase, gotBase uint64, syms []PLTEntry) {
	switch pp.arch {
	case ArchAMD64:
		patchPLTAMD64(plt, gotPLT, relaPLT, pltBase, gotBase, syms)
	case ArchARM64:
		patchPLTARM64(plt, gotPLT, relaPLT, pltBase, gotBase, syms)
	case ArchRISCV64:
		patchPLTRISCV64(plt, gotPLT, relaPLT, pltBase, gotBase, syms)
	}
}

// ── AMD64 PLT ─────────────────────────────────────────────────────────────────

func patchPLTAMD64(plt, gotPLT, relaPLT []byte, pltBase, gotBase uint64, syms []PLTEntry) {
	// PLT0: pushq *(.got.plt+8)(%rip); jmpq *(.got.plt+16)(%rip); nop
	plt[0], plt[1] = 0xff, 0x35
	putI32LE(plt[2:], ripRel32(gotBase+8, pltBase+6))
	plt[6], plt[7] = 0xff, 0x25
	putI32LE(plt[8:], ripRel32(gotBase+16, pltBase+12))
	plt[12], plt[13], plt[14], plt[15] = 0x0f, 0x1f, 0x40, 0x00

	for _, e := range syms {
		i := e.Idx
		stubBase := pltBase + 16 + uint64(i)*16
		stubOff := 16 + i*16
		gotSlotAddr := gotBase + uint64(3+i)*8
		gotSlotOff := (3 + i) * 8

		plt[stubOff+0], plt[stubOff+1] = 0xff, 0x25
		putI32LE(plt[stubOff+2:], ripRel32(gotSlotAddr, stubBase+6))
		plt[stubOff+6] = 0x68
		putI32LE(plt[stubOff+7:], int32(i))
		plt[stubOff+11] = 0xe9
		putI32LE(plt[stubOff+12:], ripRel32(pltBase, stubBase+16))

		binary.LittleEndian.PutUint64(gotPLT[gotSlotOff:], stubBase+6)

		ro := i * 24
		binary.LittleEndian.PutUint64(relaPLT[ro:], gotSlotAddr)
		binary.LittleEndian.PutUint64(relaPLT[ro+8:], (uint64(i+1)<<32)|7) // R_X86_64_JUMP_SLOT

		e.Sym.VAddr = stubBase
	}
}

// ── ARM64 PLT ─────────────────────────────────────────────────────────────────

func patchPLTARM64(plt, gotPLT, relaPLT []byte, pltBase, gotBase uint64, syms []PLTEntry) {
	plt0 := []byte{
		0xf0, 0x7b, 0xbf, 0xa9, // stp   x16, x30, [sp, #-16]!
		0x10, 0x00, 0x00, 0x90, // adrp  x16, .got.plt@PAGE
		0x11, 0x02, 0x40, 0xf9, // ldr   x17, [x16, #:lo12:.got.plt+8]
		0x10, 0x00, 0x00, 0x91, // add   x16, x16, #:lo12:.got.plt
		0x11, 0x06, 0x40, 0xf9, // ldr   x17, [x16, #16]
		0x20, 0x02, 0x1f, 0xd6, // br    x17
		0x1f, 0x20, 0x03, 0xd5, // nop
		0x1f, 0x20, 0x03, 0xd5, // nop
	}
	copy(plt, plt0)

	stub := []byte{
		0x10, 0x00, 0x00, 0x90, // adrp  x16, gotSlot@PAGE
		0x11, 0x02, 0x40, 0xf9, // ldr   x17, [x16, gotSlot@PAGEOFF]
		0x10, 0x00, 0x00, 0x91, // add   x16, x16, gotSlot@PAGEOFF
		0x20, 0x02, 0x1f, 0xd6, // br    x17
	}

	for _, e := range syms {
		i := e.Idx
		stubBase := pltBase + 32 + uint64(i)*16 // ARM64 PLT0 is 32 bytes
		stubOff := 32 + i*16
		gotSlotAddr := gotBase + uint64(3+i)*8
		gotSlotOff := (3 + i) * 8

		copy(plt[stubOff:], stub)
		binary.LittleEndian.PutUint64(gotPLT[gotSlotOff:], stubBase)

		ro := i * 24
		binary.LittleEndian.PutUint64(relaPLT[ro:], gotSlotAddr)
		binary.LittleEndian.PutUint64(relaPLT[ro+8:], (uint64(i+1)<<32)|uint64(R_AARCH64_JUMP_SLOT))
		e.Sym.VAddr = stubBase
	}
}

// ── RISC-V PLT ────────────────────────────────────────────────────────────────

func patchPLTRISCV64(plt, gotPLT, relaPLT []byte, pltBase, gotBase uint64, syms []PLTEntry) {
	plt0 := []byte{
		0x97, 0x03, 0x00, 0x00, // auipc  t2, 0
		0x33, 0x03, 0xc3, 0x41, // sub    t1, t1, t3
		0x03, 0xbe, 0x03, 0x00, // ld     t3, 0(t2)
		0x13, 0x03, 0x03, 0xfe, // addi   t1, t1, -32
		0x93, 0x8e, 0x03, 0x00, // addi   t4, t2, 0
		0x13, 0x53, 0x13, 0x00, // srli   t1, t1, 1
		0x83, 0x82, 0x83, 0x00, // ld     t0, 8(t2)
		0x67, 0x00, 0x0e, 0x00, // jr     t3
	}
	copy(plt, plt0)

	stub := []byte{
		0x17, 0x0e, 0x00, 0x00, // auipc  t3, 0
		0x03, 0x3e, 0x0e, 0x00, // ld     t3, 0(t3)
		0x67, 0x03, 0x0e, 0x00, // jalr   t1, t3
		0x13, 0x00, 0x00, 0x00, // nop
	}

	for _, e := range syms {
		i := e.Idx
		stubBase := pltBase + 32 + uint64(i)*16
		stubOff := 32 + i*16
		gotSlotAddr := gotBase + uint64(3+i)*8
		gotSlotOff := (3 + i) * 8

		copy(plt[stubOff:], stub)
		binary.LittleEndian.PutUint64(gotPLT[gotSlotOff:], stubBase)

		ro := i * 24
		binary.LittleEndian.PutUint64(relaPLT[ro:], gotSlotAddr)
		binary.LittleEndian.PutUint64(relaPLT[ro+8:], (uint64(i+1)<<32)|uint64(R_RISCV_JUMP_SLOT))
		e.Sym.VAddr = stubBase
	}
}

func ripRel32(target, ripAfter uint64) int32 {
	return int32(int64(target) - int64(ripAfter))
}

// ── buildDynamicSections (called by emitter in builder.go) ───────────────────

func (e *emitter) buildDynamicSections(dynSec *builtSection) {
	var dynstr strTab
	dynstr.add("")

	type dynEntry struct {
		tag int64
		val uint64
	}
	var entries []dynEntry

	if e.b.soname != "" {
		entries = append(entries, dynEntry{DT_SONAME, uint64(dynstr.add(e.b.soname))})
	}
	for _, lib := range e.b.needed {
		entries = append(entries, dynEntry{DT_NEEDED, uint64(dynstr.add(lib))})
	}
	if e.b.rpath != "" {
		entries = append(entries, dynEntry{DT_RUNPATH, uint64(dynstr.add(e.b.rpath))})
	}

	dynSymNameOffs := make([]uint32, len(e.b.dynSyms))
	for i, name := range e.b.dynSyms {
		dynSymNameOffs[i] = dynstr.add(name)
	}

	if sec := e.secByName[".dynstr"]; sec != nil {
		entries = append(entries, dynEntry{DT_STRTAB, sec.addr})
	}
	if sec := e.secByName[".dynsym"]; sec != nil {
		entries = append(entries, dynEntry{DT_SYMTAB, sec.addr})
		entries = append(entries, dynEntry{DT_SYMENT, symEntSize})
	}
	if sec := e.secByName[".rela.dyn"]; sec != nil {
		entries = append(entries, dynEntry{DT_RELA, sec.addr})
		entries = append(entries, dynEntry{int64(DT_RELASZ), uint64(len(sec.data))})
		entries = append(entries, dynEntry{int64(DT_RELAENT), relaEntrySize})
	}
	if sec := e.secByName[".rela.plt"]; sec != nil {
		entries = append(entries, dynEntry{DT_JMPREL, sec.addr})
		entries = append(entries, dynEntry{int64(DT_PLTRELSZ), uint64(len(sec.data))})
		entries = append(entries, dynEntry{DT_PLTREL, uint64(DT_RELA)})
	}
	if sec := e.secByName[".got.plt"]; sec != nil {
		entries = append(entries, dynEntry{int64(DT_PLTGOT), sec.addr})
	}
	if sec := e.secByName[".gnu.hash"]; sec != nil {
		entries = append(entries, dynEntry{DT_GNU_HASH, sec.addr})
	}
	if sec := e.secByName[".hash"]; sec != nil {
		entries = append(entries, dynEntry{int64(DT_HASH), sec.addr})
	}

	dynstrData := dynstr.bytes()
	for i, en := range entries {
		if en.tag == DT_STRTAB {
			tail := make([]dynEntry, len(entries[i+1:]))
			copy(tail, entries[i+1:])
			entries = append(entries[:i+1],
				append([]dynEntry{{int64(DT_STRSZ), uint64(len(dynstrData))}}, tail...)...)
			break
		}
	}
	entries = append(entries, dynEntry{DT_NULL_TAG, 0})

	var buf bytes.Buffer
	for _, en := range entries {
		var b [dynEntSize]byte
		putI64le(b[0:], en.tag)
		putU64le(b[8:], en.val)
		buf.Write(b[:])
	}

	if sec := e.secByName[".dynstr"]; sec != nil {
		sec.data = dynstrData
		sec.memSize = uint64(len(dynstrData))

		if dynsym := e.secByName[".dynsym"]; dynsym != nil {
			dynsym.link = uint32(sec.shIdx)
			symData := make([]byte, symEntSize) // null entry
			for _, nameOff := range dynSymNameOffs {
				var s [symEntSize]byte
				putU32le(s[0:], nameOff)
				s[4] = (STB_GLOBAL << 4) | STT_FUNC
				symData = append(symData, s[:]...)
			}
			dynsym.data = symData
			dynsym.memSize = uint64(len(symData))
		}
	}

	if dynSec != nil {
		dynSec.data = buf.Bytes()
		dynSec.memSize = uint64(len(dynSec.data))
	}
}

// ── GNU hash / SysV hash / version section builders ──────────────────────────

// VersionNeed declares a versioned dependency on a shared library.
type VersionNeed struct {
	Library  string
	Versions []string
}

// BuildGNUHash builds a .gnu.hash (SHT_GNU_HASH) section body.
// sortedNames must be pre-sorted with SortGNUHashSyms.
// symOffset is the .dynsym index of the first hashed symbol (typically 1).
func BuildGNUHash(sortedNames []string, symOffset uint32) []byte {
	n := len(sortedNames)
	nbuckets := uint32(n)
	if nbuckets == 0 {
		nbuckets = 1
	}
	maskwords := uint32(1)
	for maskwords < uint32((n*12+63)/64) {
		maskwords <<= 1
	}
	const shift2 = uint32(6)

	bloom := make([]uint64, maskwords)
	for _, name := range sortedNames {
		h1 := gnuHash(name)
		h2 := h1 >> shift2
		word := (h1 / 64) % maskwords
		bloom[word] |= 1 << (h1 % 64)
		bloom[word] |= 1 << (h2 % 64)
	}
	buckets := make([]uint32, nbuckets)
	for i, name := range sortedNames {
		b := gnuHash(name) % nbuckets
		if buckets[b] == 0 {
			buckets[b] = symOffset + uint32(i)
		}
	}
	chains := make([]uint32, n)
	for i, name := range sortedNames {
		h := gnuHash(name) &^ uint32(1)
		if i+1 < n && gnuHash(sortedNames[i+1])%nbuckets == gnuHash(name)%nbuckets {
			chains[i] = h
		} else {
			chains[i] = h | 1
		}
	}
	size := 4*4 + 8*int(maskwords) + 4*int(nbuckets) + 4*n
	buf := make([]byte, size)
	off := 0
	putU32le(buf[off:], nbuckets)
	off += 4
	putU32le(buf[off:], symOffset)
	off += 4
	putU32le(buf[off:], maskwords)
	off += 4
	putU32le(buf[off:], shift2)
	off += 4
	for _, w := range bloom {
		putU64le(buf[off:], w)
		off += 8
	}
	for _, b := range buckets {
		putU32le(buf[off:], b)
		off += 4
	}
	for _, c := range chains {
		putU32le(buf[off:], c)
		off += 4
	}
	return buf
}

// SortGNUHashSyms returns symNames sorted into GNU hash bucket order.
func SortGNUHashSyms(symNames []string) (sorted []string, perm []int) {
	type entry struct {
		name    string
		origIdx int
	}
	entries := make([]entry, len(symNames))
	for i, n := range symNames {
		entries[i] = entry{n, i}
	}
	nb := uint32(len(symNames))
	if nb == 0 {
		nb = 1
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return gnuHash(entries[i].name)%nb < gnuHash(entries[j].name)%nb
	})
	sorted = make([]string, len(entries))
	perm = make([]int, len(entries))
	for i, e := range entries {
		sorted[i] = e.name
		perm[i] = e.origIdx
	}
	return
}

// BuildSysVHash builds a .hash (SHT_HASH) section body.
// symNames must include the null entry at index 0 (pass "" as the first element).
func BuildSysVHash(symNames []string) []byte {
	nchain := uint32(len(symNames))
	nbuckets := nchain
	if nbuckets == 0 {
		nbuckets = 1
	}
	buckets := make([]uint32, nbuckets)
	chains := make([]uint32, nchain)
	for i, name := range symNames {
		if name == "" {
			continue
		}
		b := elfHash(name) % nbuckets
		chains[i] = buckets[b]
		buckets[b] = uint32(i)
	}
	buf := make([]byte, 4*2+4*int(nbuckets)+4*int(nchain))
	off := 0
	putU32le(buf[off:], nbuckets)
	off += 4
	putU32le(buf[off:], nchain)
	off += 4
	for _, b := range buckets {
		putU32le(buf[off:], b)
		off += 4
	}
	for _, c := range chains {
		putU32le(buf[off:], c)
		off += 4
	}
	return buf
}

// BuildVersionSym builds a .gnu.version (SHT_GNU_VERSYM) section body.
func BuildVersionSym(indices []uint16) []byte {
	buf := make([]byte, 2*len(indices))
	for i, idx := range indices {
		putU16le(buf[i*2:], idx)
	}
	return buf
}

// BuildVersionNeed builds a .gnu.version_r (SHT_GNU_VERNEED) section body.
// stringOffset must return the byte offset of a given string within .dynstr.
func BuildVersionNeed(needs []VersionNeed, stringOffset func(string) uint32) []byte {
	if len(needs) == 0 {
		return nil
	}
	const (
		verneedSize = 16
		vernauxSize = 16
	)
	var buf []byte
	versionIdx := uint16(2)
	for ni, need := range needs {
		auxCount := uint16(len(need.Versions))
		vnNext := uint32(0)
		if ni+1 < len(needs) {
			vnNext = uint32(verneedSize + int(auxCount)*vernauxSize)
		}
		var vn [verneedSize]byte
		putU16le(vn[0:], 1)
		putU16le(vn[2:], auxCount)
		putU32le(vn[4:], stringOffset(need.Library))
		putU32le(vn[8:], verneedSize)
		putU32le(vn[12:], vnNext)
		buf = append(buf, vn[:]...)
		for vi, ver := range need.Versions {
			vaNext := uint32(vernauxSize)
			if vi+1 == len(need.Versions) {
				vaNext = 0
			}
			var va [vernauxSize]byte
			putU32le(va[0:], elfHash(ver))
			putU16le(va[4:], 0)
			putU16le(va[6:], versionIdx)
			putU32le(va[8:], stringOffset(ver))
			putU32le(va[12:], vaNext)
			buf = append(buf, va[:]...)
			versionIdx++
		}
	}
	return buf
}

func gnuHash(s string) uint32 {
	h := uint32(5381)
	for i := 0; i < len(s); i++ {
		h = h*33 + uint32(s[i])
	}
	return h
}

func elfHash(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = (h << 4) + uint32(s[i])
		if g := h & 0xF0000000; g != 0 {
			h ^= g >> 24
		}
		h &^= 0xF0000000
	}
	return h
}

func appendRela(dst []byte, offset uint64, symIdx uint32, rType uint32, addend int64) []byte {
	info := (uint64(symIdx) << 32) | uint64(rType)
	var b [24]byte
	putU64le(b[0:], offset)
	putU64le(b[8:], info)
	putI64le(b[16:], addend)
	return append(dst, b[:]...)
}