// patch_arm64.go — R_AARCH64_* relocation constants and patching.
package elf

import (
	"encoding/binary"
	"fmt"
)

// R_AARCH64_* relocation type constants.
// Source: ELF for the Arm 64-bit Architecture (IHI0056).
const (
	R_AARCH64_NONE                    = uint32(0)
	R_AARCH64_ABS64                   = uint32(257)
	R_AARCH64_ABS32                   = uint32(258)
	R_AARCH64_ABS16                   = uint32(259)
	R_AARCH64_PREL64                  = uint32(260)
	R_AARCH64_PREL32                  = uint32(261)
	R_AARCH64_PREL16                  = uint32(262)
	R_AARCH64_MOVW_UABS_G0            = uint32(263)
	R_AARCH64_MOVW_UABS_G0_NC         = uint32(264)
	R_AARCH64_MOVW_UABS_G1            = uint32(265)
	R_AARCH64_MOVW_UABS_G1_NC         = uint32(266)
	R_AARCH64_MOVW_UABS_G2            = uint32(267)
	R_AARCH64_MOVW_UABS_G2_NC         = uint32(268)
	R_AARCH64_MOVW_UABS_G3            = uint32(269)
	R_AARCH64_ADR_PREL_LO21           = uint32(274)
	R_AARCH64_ADR_PREL_PG_HI21        = uint32(275)
	R_AARCH64_ADR_PREL_PG_HI21_NC     = uint32(276)
	R_AARCH64_ADD_ABS_LO12_NC         = uint32(277)
	R_AARCH64_LDST8_ABS_LO12_NC       = uint32(278)
	R_AARCH64_LDST16_ABS_LO12_NC      = uint32(284)
	R_AARCH64_LDST32_ABS_LO12_NC      = uint32(285)
	R_AARCH64_LDST64_ABS_LO12_NC      = uint32(286)
	R_AARCH64_LDST128_ABS_LO12_NC     = uint32(299)
	R_AARCH64_TSTBR14                 = uint32(279)
	R_AARCH64_CONDBR19                = uint32(280)
	R_AARCH64_JUMP26                  = uint32(282)
	R_AARCH64_CALL26                  = uint32(283)
	R_AARCH64_ADR_GOT_PAGE            = uint32(311)
	R_AARCH64_LD64_GOT_LO12_NC        = uint32(312)
	R_AARCH64_COPY                    = uint32(1024)
	R_AARCH64_GLOB_DAT                = uint32(1025)
	R_AARCH64_JUMP_SLOT               = uint32(1026)
	R_AARCH64_RELATIVE                = uint32(1027)
	R_AARCH64_TLS_DTPMOD              = uint32(1028)
	R_AARCH64_TLS_DTPREL              = uint32(1029)
	R_AARCH64_TLS_TPREL               = uint32(1030)
	R_AARCH64_TLSDESC                 = uint32(1031)
	R_AARCH64_IRELATIVE               = uint32(1032)
)

func patchAArch64(data []byte, off int, rtype uint32, P, S uint64, A int64) error {
	if off+4 > len(data) {
		return fmt.Errorf("AArch64 reloc type %d: patch offset 0x%x out of bounds", rtype, off)
	}
	insn := binary.LittleEndian.Uint32(data[off:])

	writeInsn := func(v uint32) { binary.LittleEndian.PutUint32(data[off:], v) }
	writeU64  := func(v int64)  { binary.LittleEndian.PutUint64(data[off:], uint64(v)) }
	writeU32  := func(v int64)  { binary.LittleEndian.PutUint32(data[off:], uint32(v)) }
	page      := func(addr uint64) uint64 { return addr &^ 0xFFF }

	iS := int64(S)
	iP := int64(P)

	switch rtype {
	case R_AARCH64_NONE:
		return nil

	case R_AARCH64_ABS64:
		writeU64(iS + A)

	case R_AARCH64_ABS32:
		writeU32(iS + A)

	case R_AARCH64_PREL32:
		writeU32(iS + A - iP)

	case R_AARCH64_ADR_PREL_PG_HI21, R_AARCH64_ADR_PREL_PG_HI21_NC:
		delta := int64(page(uint64(iS+A))) - int64(page(P))
		if rtype == R_AARCH64_ADR_PREL_PG_HI21 && (delta < -(1<<32) || delta >= (1<<32)) {
			return fmt.Errorf("AArch64 ADRP: offset 0x%x out of range", delta)
		}
		immlo := uint32((delta >> 12) & 0x3)
		immhi := uint32((delta >> 14) & 0x7FFFF)
		writeInsn((insn &^ 0x60FFFFE0) | (immlo << 29) | (immhi << 5))

	case R_AARCH64_ADD_ABS_LO12_NC:
		lo12 := uint32(uint64(iS+A) & 0xFFF)
		writeInsn((insn &^ (0xFFF << 10)) | (lo12 << 10))

	case R_AARCH64_LDST8_ABS_LO12_NC:
		lo12 := uint32(uint64(iS+A) & 0xFFF)
		writeInsn((insn &^ (0xFFF << 10)) | (lo12 << 10))

	case R_AARCH64_LDST16_ABS_LO12_NC:
		lo12 := uint32((uint64(iS+A) >> 1) & 0x7FF)
		writeInsn((insn &^ (0x7FF << 10)) | (lo12 << 10))

	case R_AARCH64_LDST32_ABS_LO12_NC:
		lo12 := uint32((uint64(iS+A) >> 2) & 0x3FF)
		writeInsn((insn &^ (0x3FF << 10)) | (lo12 << 10))

	case R_AARCH64_LDST64_ABS_LO12_NC:
		lo12 := uint32((uint64(iS+A) >> 3) & 0x1FF)
		writeInsn((insn &^ (0x1FF << 10)) | (lo12 << 10))

	case R_AARCH64_LDST128_ABS_LO12_NC:
		lo12 := uint32((uint64(iS+A) >> 4) & 0xFF)
		writeInsn((insn &^ (0xFF << 10)) | (lo12 << 10))

	case R_AARCH64_JUMP26, R_AARCH64_CALL26:
		delta := iS + A - iP
		if delta < -(1<<27) || delta >= (1<<27) {
			return fmt.Errorf("AArch64 B/BL: branch too far (0x%x)", delta)
		}
		imm26 := uint32((delta >> 2) & 0x3FFFFFF)
		writeInsn((insn &^ 0x3FFFFFF) | imm26)

	case R_AARCH64_CONDBR19:
		delta := iS + A - iP
		if delta < -(1<<20) || delta >= (1<<20) {
			return fmt.Errorf("AArch64 B.cond: branch too far (0x%x)", delta)
		}
		imm19 := uint32((delta >> 2) & 0x7FFFF)
		writeInsn((insn &^ (0x7FFFF << 5)) | (imm19 << 5))

	case R_AARCH64_ADR_GOT_PAGE:
		delta := int64(page(uint64(iS+A))) - int64(page(P))
		immlo := uint32((delta >> 12) & 0x3)
		immhi := uint32((delta >> 14) & 0x7FFFF)
		writeInsn((insn &^ 0x60FFFFE0) | (immlo << 29) | (immhi << 5))

	case R_AARCH64_LD64_GOT_LO12_NC:
		lo12 := uint32((uint64(iS+A) >> 3) & 0x1FF)
		writeInsn((insn &^ (0x1FF << 10)) | (lo12 << 10))

	default:
		return fmt.Errorf("AArch64: unhandled relocation type %d", rtype)
	}
	return nil
}