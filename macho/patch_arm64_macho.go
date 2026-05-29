package macho

import (
	"encoding/binary"
	"fmt"
)

// applyARM64 applies one Mach-O AArch64 relocation to data[off:].
//
// relType encoding (packed by object.go):
//   bits [3:0]  = ARM64_RELOC_* type
//   bits [9:8]  = r_length  (always 2=4B for instruction relocs, 3=8B for data)
//   bits [16]   = r_pcrel
//
// ARM64_RELOC_ADDEND is consumed at parse time and folded into A before
// this function is called.
func applyARM64(data []byte, off int, relType uint32, P, S uint64, A int64, state *pltState) error {
	rtype := relType & 0xF
	rlen := (relType >> 8) & 0x3
	_ = rlen

	switch rtype {
	case ARM64_RELOC_UNSIGNED:
		// Absolute pointer (8-byte).
		val := uint64(int64(S) + A)
		return put64(data, off, val)

	case ARM64_RELOC_BRANCH26:
		// B or BL instruction: 26-bit signed PC-relative offset (in units of 4 bytes).
		delta := int64(S) + A - int64(P)
		if delta%4 != 0 {
			return fmt.Errorf("ARM64_RELOC_BRANCH26: misaligned target delta %d at P=0x%x", delta, P)
		}
		imm26 := uint32(delta/4) & 0x3FFFFFF
		instr := binary.LittleEndian.Uint32(data[off:])
		instr = (instr & 0xFC000000) | imm26
		binary.LittleEndian.PutUint32(data[off:], instr)
		return nil

	case ARM64_RELOC_PAGE21:
		// ADRP: 21-bit page-relative immediate.
		// Read destination register from existing instruction.
		instr := binary.LittleEndian.Uint32(data[off:])
		rd := instr & 0x1F
		target := uint64(int64(S) + A)
		newInstr := encodeADRP(rd, P, target)
		binary.LittleEndian.PutUint32(data[off:], newInstr)
		return nil

	case ARM64_RELOC_PAGEOFF12:
		// ADD or LDR/STR: 12-bit page offset.
		instr := binary.LittleEndian.Uint32(data[off:])
		target := uint64(int64(S)+A) & 0xFFF
		newInstr, err := patchPageOff12(instr, target)
		if err != nil {
			return fmt.Errorf("ARM64_RELOC_PAGEOFF12 at 0x%x: %w", P, err)
		}
		binary.LittleEndian.PutUint32(data[off:], newInstr)
		return nil

	case ARM64_RELOC_GOT_LOAD_PAGE21:
		// ADRP for GOT-indirect load.  S is the stub VA; we need the GOT slot.
		gotVA, ok := state.stubToGOT[S]
		if !ok {
			gotVA = S
		}
		instr := binary.LittleEndian.Uint32(data[off:])
		rd := instr & 0x1F
		newInstr := encodeADRP(rd, P, gotVA)
		binary.LittleEndian.PutUint32(data[off:], newInstr)
		return nil

	case ARM64_RELOC_GOT_LOAD_PAGEOFF12:
		// LDR from GOT slot (8-byte aligned).
		gotVA, ok := state.stubToGOT[S]
		if !ok {
			gotVA = S
		}
		instr := binary.LittleEndian.Uint32(data[off:])
		pageOff := gotVA & 0xFFF
		newInstr, err := patchPageOff12(instr, pageOff)
		if err != nil {
			return fmt.Errorf("ARM64_RELOC_GOT_LOAD_PAGEOFF12 at 0x%x: %w", P, err)
		}
		binary.LittleEndian.PutUint32(data[off:], newInstr)
		return nil

	case ARM64_RELOC_POINTER_TO_GOT:
		// PC-relative 32-bit pointer to GOT entry.
		gotVA, ok := state.stubToGOT[S]
		if !ok {
			gotVA = S
		}
		val := int32(int64(gotVA) + A - int64(P))
		return put32(data, off, uint32(val))

	case ARM64_RELOC_SUBTRACTOR:
		// Pair reloc; handled in tandem with next reloc at parse time.
		return nil

	default:
		return fmt.Errorf("unsupported ARM64 Mach-O reloc type %d at off 0x%x", rtype, off)
	}
}

// patchPageOff12 updates the 12-bit immediate field in an ADD or LDR/STR
// instruction for a page-relative (PAGEOFF12) relocation.
func patchPageOff12(instr uint32, byteOffset uint64) (uint32, error) {
	top8 := instr >> 24

	switch {
	case top8 == 0x91:
		// ADD Xd, Xn, #imm12 — unscaled byte offset.
		imm12 := uint32(byteOffset & 0xFFF)
		return (instr & 0xFFC003FF) | (imm12 << 10), nil

	case top8&0xBF == 0x39: // 0x39 (LDRB) or 0x79 (LDRH)
		// 8-bit or 16-bit load/store — offset is not scaled, use as-is.
		scale := uint64(1)
		if top8&0x40 != 0 {
			scale = 2
		}
		imm12 := uint32((byteOffset / scale) & 0xFFF)
		return (instr & 0xFFC003FF) | (imm12 << 10), nil

	case top8 == 0xB9: // LDR/STR 32-bit
		imm12 := uint32((byteOffset >> 2) & 0xFFF)
		return (instr & 0xFFC003FF) | (imm12 << 10), nil

	case top8 == 0xF9: // LDR/STR 64-bit
		imm12 := uint32((byteOffset >> 3) & 0xFFF)
		return (instr & 0xFFC003FF) | (imm12 << 10), nil

	case top8 == 0x3D: // LDR/STR 128-bit (SIMD)
		imm12 := uint32((byteOffset >> 4) & 0xFFF)
		return (instr & 0xFFC003FF) | (imm12 << 10), nil

	default:
		// Generic 4-byte scale fallback (covers most load/store patterns).
		size := (instr >> 30) & 0x3 // [31:30] = access size
		scale := uint64(1) << size
		imm12 := uint32((byteOffset / scale) & 0xFFF)
		return (instr & 0xFFC003FF) | (imm12 << 10), nil
	}
}