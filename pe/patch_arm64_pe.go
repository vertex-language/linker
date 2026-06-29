package pe

import (
	"encoding/binary"
	"fmt"
)

type arm64Patcher struct {
	coreBase uint64
	addr64s  []BaseRelocSite
}

func (p *arm64Patcher) BaseRelocSites() []BaseRelocSite { return p.addr64s }

func (p *arm64Patcher) Apply(data []byte, off int, relType uint32, P, S uint64, A int64) error {
	switch relType {

	case relARM64Absolute:
		return nil

	case relARM64Addr64:
		if off+8 > len(data) {
			return fmt.Errorf("ARM64 ADDR64 write at %d out of bounds", off)
		}
		binary.LittleEndian.PutUint64(data[off:], uint64(int64(S)+A))
		p.addr64s = append(p.addr64s, BaseRelocSite{VA: P})

	case relARM64Addr32:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 ADDR32 write at %d out of bounds", off)
		}
		binary.LittleEndian.PutUint32(data[off:], uint32(int32(int64(S)+A)))

	case relARM64Addr32NB:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 ADDR32NB write at %d out of bounds", off)
		}
		v := int64(S) + A - int64(p.coreBase)
		binary.LittleEndian.PutUint32(data[off:], uint32(int32(v)))

	case relARM64Rel32:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 REL32 write at %d out of bounds", off)
		}
		v := int64(S) + A - int64(P)
		if v < -0x80000000 || v > 0x7FFFFFFF {
			return fmt.Errorf("ARM64 REL32 overflow: %d", v)
		}
		binary.LittleEndian.PutUint32(data[off:], uint32(int32(v)))

	case relARM64Branch26:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 BRANCH26 write at %d out of bounds", off)
		}
		delta := (int64(S) + A - int64(P)) / 4
		if delta < -(1<<25) || delta >= (1<<25) {
			return fmt.Errorf("ARM64 BRANCH26 overflow: delta=%d", delta)
		}
		insn := binary.LittleEndian.Uint32(data[off:])
		insn = (insn &^ 0x03FFFFFF) | (uint32(delta) & 0x03FFFFFF)
		binary.LittleEndian.PutUint32(data[off:], insn)

	case relARM64Branch19:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 BRANCH19 write at %d out of bounds", off)
		}
		delta := (int64(S) + A - int64(P)) / 4
		if delta < -(1<<18) || delta >= (1<<18) {
			return fmt.Errorf("ARM64 BRANCH19 overflow: delta=%d", delta)
		}
		insn := binary.LittleEndian.Uint32(data[off:])
		insn = (insn &^ (0x7FFFF << 5)) | ((uint32(delta) & 0x7FFFF) << 5)
		binary.LittleEndian.PutUint32(data[off:], insn)

	case relARM64Branch14:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 BRANCH14 write at %d out of bounds", off)
		}
		delta := (int64(S) + A - int64(P)) / 4
		if delta < -(1<<13) || delta >= (1<<13) {
			return fmt.Errorf("ARM64 BRANCH14 overflow: delta=%d", delta)
		}
		insn := binary.LittleEndian.Uint32(data[off:])
		insn = (insn &^ (0x3FFF << 5)) | ((uint32(delta) & 0x3FFF) << 5)
		binary.LittleEndian.PutUint32(data[off:], insn)

	case relARM64PagebaseRel21:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 PAGEBASE_REL21 write at %d out of bounds", off)
		}
		target := uint64(int64(S) + A)
		pageDelta := int64(target>>12) - int64(P>>12)
		if pageDelta < -(1<<20) || pageDelta >= (1<<20) {
			return fmt.Errorf("ARM64 ADRP page delta overflow: %d", pageDelta)
		}
		immlo := uint32(pageDelta & 0x3)
		immhi := uint32((pageDelta >> 2) & 0x7FFFF)
		insn := binary.LittleEndian.Uint32(data[off:])
		insn = (insn &^ 0x60FFFFE0) | (immlo << 29) | (immhi << 5)
		binary.LittleEndian.PutUint32(data[off:], insn)

	case relARM64Rel21:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 REL21 write at %d out of bounds", off)
		}
		delta := int64(S) + A - int64(P)
		if delta < -(1<<20) || delta >= (1<<20) {
			return fmt.Errorf("ARM64 ADR REL21 overflow: %d", delta)
		}
		immlo := uint32(delta & 0x3)
		immhi := uint32((delta >> 2) & 0x7FFFF)
		insn := binary.LittleEndian.Uint32(data[off:])
		insn = (insn &^ 0x60FFFFE0) | (immlo << 29) | (immhi << 5)
		binary.LittleEndian.PutUint32(data[off:], insn)

	case relARM64PageOffset12A:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 PAGEOFFSET_12A write at %d out of bounds", off)
		}
		imm12 := uint32(uint64(int64(S)+A) & 0xFFF)
		insn := binary.LittleEndian.Uint32(data[off:])
		insn = (insn &^ (0xFFF << 10)) | (imm12 << 10)
		binary.LittleEndian.PutUint32(data[off:], insn)

	case relARM64PageOffset12L:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 PAGEOFFSET_12L write at %d out of bounds", off)
		}
		insn := binary.LittleEndian.Uint32(data[off:])
		size := insn >> 30
		scale := uint64(1 << size)
		pageOff := uint64(int64(S)+A) & 0xFFF
		imm12 := uint32(pageOff / scale)
		insn = (insn &^ (0xFFF << 10)) | (imm12 << 10)
		binary.LittleEndian.PutUint32(data[off:], insn)

	case relARM64Section:
		if off+2 > len(data) {
			return fmt.Errorf("ARM64 SECTION write at %d out of bounds", off)
		}
		binary.LittleEndian.PutUint16(data[off:], 0)

	case relARM64SecRel, relARM64SecRelLow12A, relARM64SecRelHigh12A, relARM64SecRelLow12L:
		if off+4 > len(data) {
			return fmt.Errorf("ARM64 SECREL write at %d out of bounds", off)
		}
		binary.LittleEndian.PutUint32(data[off:], uint32(S+uint64(A)))

	case relARM64Token:
		return nil

	default:
		return fmt.Errorf("unsupported ARM64 COFF relocation type 0x%04X", relType)
	}
	return nil
}

// ── ARM64 PLT patcher ─────────────────────────────────────────────────────────

type arm64PLTPatcher struct {
	iatLayout *IATLayout
}

func (p *arm64PLTPatcher) PatchPLT(
	plt, gotPLT []byte,
	pltBase, gotBase uint64,
	syms []PLTEntry,
) {
	if p.iatLayout == nil {
		return
	}
	const (
		pltHdrSize  = 16
		pltEntSz    = 16
		gotResSlots = 3
	)
	for _, s := range syms {
		slot := p.iatLayout.SlotOf[s.Idx]
		iatVA := gotBase + uint64(gotResSlots+slot)*8
		thunkVA := pltBase + uint64(pltHdrSize+s.Idx*pltEntSz)
		tOff := pltHdrSize + s.Idx*pltEntSz

		thunkPage := thunkVA &^ uint64(0xFFF)
		iatPage := iatVA &^ uint64(0xFFF)
		pageDelta := int64(iatPage>>12) - int64(thunkPage>>12)
		immlo := uint32(pageDelta & 0x3)
		immhi := uint32((pageDelta >> 2) & 0x7FFFF)
		adrp := uint32(0x90000011) | (immlo << 29) | (immhi << 5)

		pageOff := iatVA & 0xFFF
		scaledOff := uint32(pageOff / 8)
		ldr := uint32(0xF9400231) | (scaledOff << 10)
		br := uint32(0xD61F0220)
		nop := uint32(0xD503201F)

		binary.LittleEndian.PutUint32(plt[tOff:], adrp)
		binary.LittleEndian.PutUint32(plt[tOff+4:], ldr)
		binary.LittleEndian.PutUint32(plt[tOff+8:], br)
		binary.LittleEndian.PutUint32(plt[tOff+12:], nop)

		s.Sym.VAddr = thunkVA
	}
}