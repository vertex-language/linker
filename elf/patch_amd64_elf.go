// patch_amd64.go — R_X86_64_* relocation constants and patching.
package elf

import (
	"encoding/binary"
	"fmt"
)

// R_X86_64_* relocation type constants.
// Source: System V AMD64 ABI §4.4.
const (
	R_X86_64_NONE          = uint32(0)
	R_X86_64_64            = uint32(1)  // S + A
	R_X86_64_PC32          = uint32(2)  // S + A − P
	R_X86_64_GOT32         = uint32(3)  // G + A
	R_X86_64_PLT32         = uint32(4)  // L + A − P
	R_X86_64_COPY          = uint32(5)
	R_X86_64_GLOB_DAT      = uint32(6)  // S
	R_X86_64_JUMP_SLOT     = uint32(7)  // S
	R_X86_64_RELATIVE      = uint32(8)  // B + A
	R_X86_64_GOTPCREL      = uint32(9)  // G + GOT + A − P
	R_X86_64_32            = uint32(10) // S + A (zero-extend)
	R_X86_64_32S           = uint32(11) // S + A (sign-extend)
	R_X86_64_16            = uint32(12)
	R_X86_64_PC16          = uint32(13)
	R_X86_64_8             = uint32(14)
	R_X86_64_PC8           = uint32(15)
	R_X86_64_DTPMOD64      = uint32(16)
	R_X86_64_DTPOFF64      = uint32(17)
	R_X86_64_TPOFF64       = uint32(18)
	R_X86_64_TLSGD         = uint32(19)
	R_X86_64_TLSLD         = uint32(20)
	R_X86_64_DTPOFF32      = uint32(21)
	R_X86_64_GOTTPOFF      = uint32(22)
	R_X86_64_TPOFF32       = uint32(23)
	R_X86_64_PC64          = uint32(24) // S + A − P
	R_X86_64_GOTOFF64      = uint32(25)
	R_X86_64_GOTPC32       = uint32(26)
	R_X86_64_GOT64         = uint32(27)
	R_X86_64_GOTPCREL64    = uint32(28)
	R_X86_64_GOTPC64       = uint32(29)
	R_X86_64_IRELATIVE     = uint32(37)
	R_X86_64_GOTPCRELX     = uint32(41)
	R_X86_64_REX_GOTPCRELX = uint32(42)
)

// elfPatcher dispatches ELF relocations to the correct arch implementation.
type elfPatcher struct{ arch uint16 }

func (p *elfPatcher) Apply(data []byte, off int, relType uint32, P, S uint64, A int64) error {
	switch p.arch {
	case ArchAMD64:
		return patchAMD64(data, off, relType, P, S, A)
	case ArchARM64:
		return patchAArch64(data, off, relType, P, S, A)
	case ArchRISCV64:
		return patchRISCV(data, off, relType, P, S, A)
	default:
		return fmt.Errorf("patcher: unsupported arch 0x%x", p.arch)
	}
}

func patchAMD64(data []byte, off int, rtype uint32, P, S uint64, A int64) error {
	put32 := func(v int64) error {
		if v < -0x80000000 || v > 0x7FFFFFFF {
			return fmt.Errorf("R_X86_64 type %d: value 0x%x overflows int32", rtype, v)
		}
		binary.LittleEndian.PutUint32(data[off:], uint32(v))
		return nil
	}
	put32u := func(v int64) error {
		if uint64(v) > 0xFFFFFFFF {
			return fmt.Errorf("R_X86_64 type %d: value 0x%x overflows uint32", rtype, v)
		}
		binary.LittleEndian.PutUint32(data[off:], uint32(v))
		return nil
	}
	put64 := func(v int64) error {
		binary.LittleEndian.PutUint64(data[off:], uint64(v))
		return nil
	}

	iS := int64(S)
	iP := int64(P)

	switch rtype {
	case R_X86_64_NONE:
		return nil
	case R_X86_64_64:
		return put64(iS + A)
	case R_X86_64_PC32, R_X86_64_PLT32:
		return put32(iS + A - iP)
	case R_X86_64_32:
		return put32u(iS + A)
	case R_X86_64_32S:
		return put32(iS + A)
	case R_X86_64_PC64:
		return put64(iS + A - iP)
	default:
		return fmt.Errorf("R_X86_64: unhandled relocation type %d", rtype)
	}
}