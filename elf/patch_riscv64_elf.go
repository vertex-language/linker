// patch_riscv64.go — R_RISCV_* relocation constants and patching.
package elf

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// R_RISCV_* relocation type constants.
// Source: RISC-V ELF psABI.
const (
	R_RISCV_NONE          = uint32(0)
	R_RISCV_32            = uint32(1)  // S + A
	R_RISCV_64            = uint32(2)  // S + A
	R_RISCV_RELATIVE      = uint32(3)  // B + A
	R_RISCV_COPY          = uint32(4)
	R_RISCV_JUMP_SLOT     = uint32(5)  // S
	R_RISCV_TLS_DTPMOD32  = uint32(6)
	R_RISCV_TLS_DTPMOD64  = uint32(7)
	R_RISCV_TLS_DTPREL32  = uint32(8)
	R_RISCV_TLS_DTPREL64  = uint32(9)
	R_RISCV_TLS_TPREL32   = uint32(10)
	R_RISCV_TLS_TPREL64   = uint32(11)
	R_RISCV_IRELATIVE     = uint32(58)
	R_RISCV_BRANCH        = uint32(16) // S + A − P [12:1]
	R_RISCV_JAL           = uint32(17) // S + A − P [20:1]
	R_RISCV_CALL          = uint32(18) // S + A − P (AUIPC+JALR pair)
	R_RISCV_CALL_PLT      = uint32(19)
	R_RISCV_GOT_HI20      = uint32(20)
	R_RISCV_PCREL_HI20    = uint32(23) // S + A − P [31:12] AUIPC
	R_RISCV_PCREL_LO12_I  = uint32(24) // S − P [11:0] I-type
	R_RISCV_PCREL_LO12_S  = uint32(25) // S − P [11:0] S-type
	R_RISCV_HI20          = uint32(26) // S + A [31:12] LUI
	R_RISCV_LO12_I        = uint32(27) // S + A [11:0] I-type
	R_RISCV_LO12_S        = uint32(28) // S + A [11:0] S-type
	R_RISCV_TPREL_HI20    = uint32(29)
	R_RISCV_TPREL_LO12_I  = uint32(30)
	R_RISCV_TPREL_LO12_S  = uint32(31)
	R_RISCV_TPREL_ADD     = uint32(32)
	R_RISCV_ADD8          = uint32(33)
	R_RISCV_ADD16         = uint32(34)
	R_RISCV_ADD32         = uint32(35)
	R_RISCV_ADD64         = uint32(36)
	R_RISCV_SUB8          = uint32(37)
	R_RISCV_SUB16         = uint32(38)
	R_RISCV_SUB32         = uint32(39)
	R_RISCV_SUB64         = uint32(40)
	R_RISCV_ALIGN         = uint32(43)
	R_RISCV_RVC_BRANCH    = uint32(44)
	R_RISCV_RVC_JUMP      = uint32(45)
	R_RISCV_RELAX         = uint32(51)
	R_RISCV_SUB6          = uint32(52)
	R_RISCV_SET6          = uint32(53)
	R_RISCV_SET8          = uint32(54)
	R_RISCV_SET16         = uint32(55)
	R_RISCV_SET32         = uint32(56)
	R_RISCV_32_PCREL      = uint32(57)
	R_RISCV_PLT32         = uint32(59)
)

func patchRISCV(data []byte, off int, rtype uint32, P, S uint64, A int64) error {
	if off+4 > len(data) {
		return fmt.Errorf("RISC-V reloc type %d: patch offset 0x%x out of bounds", rtype, off)
	}
	insn := binary.LittleEndian.Uint32(data[off:])

	writeInsn := func(v uint32) { binary.LittleEndian.PutUint32(data[off:], v) }

	// %hi(x) = (x + 0x800) >> 12 ;  %lo(x) = x & 0xFFF (sign-extended)
	hi20 := func(x int64) int64 { return (x + 0x800) >> 12 }
	lo12 := func(x int64) int64 { return x & 0xFFF }
	signExt12 := func(v int64) int64 {
		v &= 0xFFF
		if v&0x800 != 0 {
			v |= ^int64(0xFFF)
		}
		return v
	}
	setUtype := func(imm int64) {
		writeInsn((insn &^ 0xFFFFF000) | (uint32(imm&0xFFFFF) << 12))
	}
	setItype := func(imm int64) {
		writeInsn((insn &^ 0xFFF00000) | (uint32(signExt12(imm)&0xFFF) << 20))
	}

	iS := int64(S)
	iP := int64(P)

	switch rtype {
	case R_RISCV_NONE, R_RISCV_ALIGN, R_RISCV_RELAX:
		return nil

	case R_RISCV_32:
		binary.LittleEndian.PutUint32(data[off:], uint32(iS+A))

	case R_RISCV_64:
		binary.LittleEndian.PutUint64(data[off:], uint64(iS+A))

	case R_RISCV_JAL:
		delta := iS + A - iP
		if delta < -(1<<20) || delta >= (1<<20) {
			return fmt.Errorf("RISC-V JAL: target out of range (0x%x)", delta)
		}
		imm := uint32(delta)
		jtype := (bits.RotateLeft32((imm>>1)&0x3FF, 21) & 0x7FE00000) |
			((imm>>11)&1)<<20 |
			((imm>>12)&0xFF)<<12 |
			((imm>>20)&1)<<31
		writeInsn((insn &^ 0xFFFFF000) | jtype)

	case R_RISCV_CALL, R_RISCV_CALL_PLT:
		if off+8 > len(data) {
			return fmt.Errorf("RISC-V CALL: not enough space for AUIPC+JALR pair")
		}
		delta := iS + A - iP
		insn0 := binary.LittleEndian.Uint32(data[off:])
		insn1 := binary.LittleEndian.Uint32(data[off+4:])
		binary.LittleEndian.PutUint32(data[off:], (insn0&^0xFFFFF000)|uint32(hi20(delta)&0xFFFFF)<<12)
		binary.LittleEndian.PutUint32(data[off+4:], (insn1&^0xFFF00000)|uint32(lo12(delta)&0xFFF)<<20)

	case R_RISCV_BRANCH:
		delta := iS + A - iP
		if delta < -(1<<12) || delta >= (1<<12) {
			return fmt.Errorf("RISC-V BRANCH: target out of range (0x%x)", delta)
		}
		imm := uint32(delta)
		btype := ((imm>>12)&1)<<31 |
			((imm>>5)&0x3F)<<25 |
			((imm>>1)&0xF)<<8 |
			((imm>>11)&1)<<7
		writeInsn((insn &^ 0xFE000F80) | btype)

	case R_RISCV_PCREL_HI20, R_RISCV_GOT_HI20:
		setUtype(hi20(iS + A - iP))

	case R_RISCV_PCREL_LO12_I:
		setItype(lo12(iS + A))

	case R_RISCV_PCREL_LO12_S:
		imm := lo12(iS + A)
		stype := (uint32(imm>>5)&0x7F)<<25 | (uint32(imm)&0x1F)<<7
		writeInsn((insn &^ 0xFE000F80) | stype)

	case R_RISCV_HI20:
		setUtype(hi20(iS + A))

	case R_RISCV_LO12_I:
		setItype(lo12(iS + A))

	case R_RISCV_LO12_S:
		imm := lo12(iS + A)
		stype := (uint32(imm>>5)&0x7F)<<25 | (uint32(imm)&0x1F)<<7
		writeInsn((insn &^ 0xFE000F80) | stype)

	case R_RISCV_32_PCREL, R_RISCV_PLT32:
		binary.LittleEndian.PutUint32(data[off:], uint32(iS+A-iP))

	default:
		return fmt.Errorf("RISC-V: unhandled relocation type %d", rtype)
	}
	return nil
}

// Silence "imported and not used" for bits.
var _ = bits.RotateLeft32