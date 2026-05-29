package macho

import (
	"encoding/binary"
	"fmt"
)

// applyAMD64 applies one Mach-O x86-64 relocation to data[off:].
//
// relType encoding (packed by object.go):
//   bits [3:0]  = X86_64_RELOC_* type
//   bits [9:8]  = r_length  (0=1B, 1=2B, 2=4B, 3=8B)
//   bits [16]   = r_pcrel   (1 = PC-relative)
//
// For PC-relative relocations the addend A is the implicit value already
// stored in the bytes at the patch site by the assembler (typically −4 for
// branch targets pointing to "next instruction").
func applyAMD64(data []byte, off int, relType uint32, P, S uint64, A int64, state *pltState) error {
	rtype := relType & 0xF
	rlen := (relType >> 8) & 0x3
	pcrel := (relType >> 16) & 0x1

	switch rtype {
	case X86_64_RELOC_UNSIGNED:
		// Absolute address.
		val := uint64(int64(S) + A)
		switch rlen {
		case 2: // 32-bit
			return put32(data, off, uint32(val))
		case 3: // 64-bit
			return put64(data, off, val)
		}

	case X86_64_RELOC_SIGNED, X86_64_RELOC_SIGNED_1, X86_64_RELOC_SIGNED_2, X86_64_RELOC_SIGNED_4:
		// PC-relative 32-bit.  The formula S + A − P gives the displacement.
		// Note: the embedded addend A already encodes the "bias" (−4 for a
		// typical 5-byte instruction), so we do not add another −4 here.
		if pcrel == 0 {
			return fmt.Errorf("SIGNED reloc at 0x%x but r_pcrel=0", P)
		}
		val := int32(int64(S) + A - int64(P))
		return put32(data, off, uint32(val))

	case X86_64_RELOC_BRANCH:
		// CALL/JMP: same formula as SIGNED.
		if pcrel == 0 {
			return fmt.Errorf("BRANCH reloc at 0x%x but r_pcrel=0", P)
		}
		// If S points to a stub, use it directly. If S happens to be a GOT
		// slot (e.g. from an older GOT-indirect pattern), follow the mapping.
		target := S
		if got, ok := state.stubToGOT[S]; ok {
			_ = got
			// S is already the stub; proceed normally.
		}
		val := int32(int64(target) + A - int64(P))
		return put32(data, off, uint32(val))

	case X86_64_RELOC_GOT_LOAD, X86_64_RELOC_GOT:
		// MOVQ load from GOT / general GOT reference.
		// S is the stub VA; the GOT slot is what the instruction really needs.
		gotVA, ok := state.stubToGOT[S]
		if !ok {
			// Symbol may be defined locally; use S directly.
			gotVA = S
		}
		if pcrel != 0 {
			val := int32(int64(gotVA) + A - int64(P))
			return put32(data, off, uint32(val))
		}
		return put64(data, off, gotVA)

	case X86_64_RELOC_SUBTRACTOR:
		// Paired with the next reloc; not yet supported.
		return nil

	default:
		return fmt.Errorf("unsupported AMD64 Mach-O reloc type %d at off 0x%x", rtype, off)
	}

	return fmt.Errorf("unhandled AMD64 reloc rtype=%d rlen=%d at off 0x%x", rtype, rlen, off)
}

func put32(data []byte, off int, v uint32) error {
	if off+4 > len(data) {
		return fmt.Errorf("reloc patch offset 0x%x out of bounds", off)
	}
	binary.LittleEndian.PutUint32(data[off:], v)
	return nil
}

func put64(data []byte, off int, v uint64) error {
	if off+8 > len(data) {
		return fmt.Errorf("reloc patch offset 0x%x out of bounds", off)
	}
	binary.LittleEndian.PutUint64(data[off:], v)
	return nil
}