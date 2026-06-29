package pe

import (
	"encoding/binary"
	"fmt"
)

type amd64Patcher struct {
	coreBase uint64
	addr64s  []BaseRelocSite
}

func (p *amd64Patcher) BaseRelocSites() []BaseRelocSite { return p.addr64s }

func (p *amd64Patcher) Apply(data []byte, off int, relType uint32, P, S uint64, A int64) error {
	switch relType {

	case relAMD64Absolute:
		return nil

	case relAMD64Addr64:
		if off+8 > len(data) {
			return fmt.Errorf("ADDR64 write at %d out of bounds", off)
		}
		binary.LittleEndian.PutUint64(data[off:], uint64(int64(S)+A))
		p.addr64s = append(p.addr64s, BaseRelocSite{VA: P})

	case relAMD64Addr32:
		if off+4 > len(data) {
			return fmt.Errorf("ADDR32 write at %d out of bounds", off)
		}
		binary.LittleEndian.PutUint32(data[off:], uint32(int32(int64(S)+A)))

	case relAMD64Addr32NB:
		if off+4 > len(data) {
			return fmt.Errorf("ADDR32NB write at %d out of bounds", off)
		}
		v := int64(S) + A - int64(p.coreBase)
		binary.LittleEndian.PutUint32(data[off:], uint32(int32(v)))

	case relAMD64Rel32:
		return amd64WriteRel32(data, off, int64(S)+A-int64(P)-4)
	case relAMD64Rel32_1:
		return amd64WriteRel32(data, off, int64(S)+A-int64(P)-5)
	case relAMD64Rel32_2:
		return amd64WriteRel32(data, off, int64(S)+A-int64(P)-6)
	case relAMD64Rel32_3:
		return amd64WriteRel32(data, off, int64(S)+A-int64(P)-7)
	case relAMD64Rel32_4:
		return amd64WriteRel32(data, off, int64(S)+A-int64(P)-8)
	case relAMD64Rel32_5:
		return amd64WriteRel32(data, off, int64(S)+A-int64(P)-9)

	case relAMD64Section:
		if off+2 > len(data) {
			return fmt.Errorf("SECTION write at %d out of bounds", off)
		}
		binary.LittleEndian.PutUint16(data[off:], 0)

	case relAMD64SecRel, relAMD64SecRel7:
		if off+4 > len(data) {
			return fmt.Errorf("SECREL write at %d out of bounds", off)
		}
		binary.LittleEndian.PutUint32(data[off:], uint32(S+uint64(A)))

	case relAMD64Token:
		return nil

	default:
		return fmt.Errorf("unsupported AMD64 COFF relocation type 0x%04X", relType)
	}
	return nil
}

func amd64WriteRel32(data []byte, off int, v int64) error {
	if off+4 > len(data) {
		return fmt.Errorf("REL32 write at %d out of bounds", off)
	}
	if v < -0x80000000 || v > 0x7FFFFFFF {
		return fmt.Errorf("REL32 overflow: %d does not fit in int32", v)
	}
	binary.LittleEndian.PutUint32(data[off:], uint32(int32(v)))
	return nil
}

// ── AMD64 PLT patcher ─────────────────────────────────────────────────────────

type amd64PLTPatcher struct {
	iatLayout *IATLayout
}

func (p *amd64PLTPatcher) PatchPLT(
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
		rel32 := int32(int64(iatVA) - int64(thunkVA+6))
		tOff := pltHdrSize + s.Idx*pltEntSz
		plt[tOff+0] = 0xFF
		plt[tOff+1] = 0x25
		binary.LittleEndian.PutUint32(plt[tOff+2:], uint32(rel32))
		for k := 6; k < pltEntSz; k++ {
			plt[tOff+k] = 0x90
		}
		s.Sym.VAddr = thunkVA
	}
}