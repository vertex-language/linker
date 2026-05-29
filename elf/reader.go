// reader.go — bounds-checked little-endian byte reader and ELF struct offsets.
package elf

import (
	"encoding/binary"
	"fmt"
)

// ── ELF struct offsets ────────────────────────────────────────────────────────

// Elf64_Ehdr offsets.
const (
	ehoff_type      = 16
	ehoff_machine   = 18
	ehoff_version   = 20
	ehoff_entry     = 24
	ehoff_phoff     = 32
	ehoff_shoff     = 40
	ehoff_flags     = 48
	ehoff_ehsize    = 52
	ehoff_phentsize = 54
	ehoff_phnum     = 56
	ehoff_shentsize = 58
	ehoff_shnum     = 60
	ehoff_shstrndx  = 62
	ehdrSize        = 64
)

// Elf64_Shdr offsets.
const (
	shoff_name      = 0
	shoff_type      = 4
	shoff_flags     = 8
	shoff_addr      = 16
	shoff_offset    = 24
	shoff_size      = 32
	shoff_link      = 40
	shoff_info      = 44
	shoff_addralign = 48
	shoff_entsize   = 56
	shdrSize        = 64
)

// Elf64_Sym offsets.
const (
	symoff_name  = 0
	symoff_info  = 4
	symoff_other = 5
	symoff_shndx = 6
	symoff_value = 8
	symoff_size  = 16
	symEntSize   = 24
)

// Elf64_Rela offsets.
const (
	relaoff_offset = 0
	relaoff_info   = 8
	relaoff_addend = 16
	relaEntrySize  = 24
)

// Elf64_Dyn offsets.
const (
	dynoff_tag = 0
	dynoff_val = 8
	dynEntSize = 16
)

// ELF identification constants (duplicated from constants.go for parser independence).
const (
	elfClass64  = 2
	elfData2LSB = 1
	etRel       = 1
	etDyn       = 3
	etExec      = 2
	shnUndef    = 0
	shnAbs      = 0xFFF1
	shnCommon   = 0xFFF2
	shnXindex   = 0xFFFF
	shnLoreserve = 0xFF00
	shtSymtab   = 2
	shtStrtab   = 3
	shtRela     = 4
	shtNobits   = 8
	shtDynsym   = 11
	shtDynamic  = 6
	shtGroup    = 17
)

func relaSymIdx(info uint64) uint32 { return uint32(info >> 32) }
func relaType(info uint64) uint32   { return uint32(info) }
func stBind(info uint8) uint8       { return info >> 4 }
func stType(info uint8) uint8       { return info & 0xf }

// ── Bounds-checked reader ─────────────────────────────────────────────────────

type reader struct{ data []byte }

func newReader(data []byte) *reader { return &reader{data} }

func (r *reader) u16(off int) (uint16, error) {
	if off+2 > len(r.data) {
		return 0, fmt.Errorf("u16 read at 0x%x: out of bounds", off)
	}
	return binary.LittleEndian.Uint16(r.data[off:]), nil
}

func (r *reader) u32(off int) (uint32, error) {
	if off+4 > len(r.data) {
		return 0, fmt.Errorf("u32 read at 0x%x: out of bounds", off)
	}
	return binary.LittleEndian.Uint32(r.data[off:]), nil
}

func (r *reader) u32be(off int) (uint32, error) {
	if off+4 > len(r.data) {
		return 0, fmt.Errorf("u32be read at 0x%x: out of bounds", off)
	}
	return binary.BigEndian.Uint32(r.data[off:]), nil
}

func (r *reader) u64(off int) (uint64, error) {
	if off+8 > len(r.data) {
		return 0, fmt.Errorf("u64 read at 0x%x: out of bounds", off)
	}
	return binary.LittleEndian.Uint64(r.data[off:]), nil
}

func (r *reader) u64be(off int) (uint64, error) {
	if off+8 > len(r.data) {
		return 0, fmt.Errorf("u64be read at 0x%x: out of bounds", off)
	}
	return binary.BigEndian.Uint64(r.data[off:]), nil
}

func (r *reader) i64(off int) (int64, error) {
	v, err := r.u64(off)
	return int64(v), err
}

// slice returns a copy of data[off : off+size].
func (r *reader) slice(off, size int) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if off+size > len(r.data) {
		return nil, fmt.Errorf("slice [0x%x:0x%x] out of bounds (len=%d)", off, off+size, len(r.data))
	}
	out := make([]byte, size)
	copy(out, r.data[off:])
	return out, nil
}

// view returns data[off : off+size] without copying.
func (r *reader) view(off, size int) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if off+size > len(r.data) {
		return nil, fmt.Errorf("view [0x%x:0x%x] out of bounds (len=%d)", off, off+size, len(r.data))
	}
	return r.data[off : off+size], nil
}

// cstr reads a NUL-terminated string from strtab starting at off.
func cstr(strtab []byte, off uint32) (string, error) {
	if int(off) >= len(strtab) {
		return "", fmt.Errorf("cstr: offset 0x%x out of bounds (len=%d)", off, len(strtab))
	}
	end := int(off)
	for end < len(strtab) && strtab[end] != 0 {
		end++
	}
	return string(strtab[off:end]), nil
}

func alignUp(v, align uint64) uint64 {
	if align <= 1 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// putU16le / putU32le / putU64le / putI64le — in-place LE writes.
func putU16le(b []byte, v uint16) { binary.LittleEndian.PutUint16(b, v) }
func putU32le(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func putU64le(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
func putI64le(b []byte, v int64)  { binary.LittleEndian.PutUint64(b, uint64(v)) }