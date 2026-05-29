package macho

import (
	"encoding/binary"
	"fmt"
)

// reader is a bounds-checked little-endian reader over a byte slice.
type reader struct {
	data []byte
	name string // file/section name for error messages
}

func newReader(data []byte, name string) *reader { return &reader{data: data, name: name} }

func (r *reader) checkBounds(off, size int) error {
	if off < 0 || size < 0 || off+size > len(r.data) {
		return fmt.Errorf("%s: read [%d, %d) out of bounds (len=%d)", r.name, off, off+size, len(r.data))
	}
	return nil
}

func (r *reader) U8(off int) (uint8, error) {
	if err := r.checkBounds(off, 1); err != nil {
		return 0, err
	}
	return r.data[off], nil
}

func (r *reader) U16(off int) (uint16, error) {
	if err := r.checkBounds(off, 2); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(r.data[off:]), nil
}

func (r *reader) U32(off int) (uint32, error) {
	if err := r.checkBounds(off, 4); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(r.data[off:]), nil
}

func (r *reader) I32(off int) (int32, error) {
	v, err := r.U32(off)
	return int32(v), err
}

func (r *reader) U64(off int) (uint64, error) {
	if err := r.checkBounds(off, 8); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(r.data[off:]), nil
}

func (r *reader) Bytes(off, size int) ([]byte, error) {
	if err := r.checkBounds(off, size); err != nil {
		return nil, err
	}
	out := make([]byte, size)
	copy(out, r.data[off:off+size])
	return out, nil
}

// CString reads a null-terminated string starting at off, up to maxLen bytes.
func (r *reader) CString(off, maxLen int) (string, error) {
	if err := r.checkBounds(off, 1); err != nil {
		return "", err
	}
	end := off
	for end < len(r.data) && end < off+maxLen && r.data[end] != 0 {
		end++
	}
	return string(r.data[off:end]), nil
}

// FixedString reads a null-padded string of exactly n bytes.
func (r *reader) FixedString(off, n int) (string, error) {
	if err := r.checkBounds(off, n); err != nil {
		return "", err
	}
	b := r.data[off : off+n]
	end := n
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return string(b[:end]), nil
}

// ── ULEB128 / SLEB128 ─────────────────────────────────────────────────────────

// readULEB128 decodes an unsigned LEB128 integer starting at off.
// Returns the value and the number of bytes consumed.
func readULEB128(data []byte, off int) (uint64, int, error) {
	var result uint64
	var shift uint
	for i := 0; ; i++ {
		if off+i >= len(data) {
			return 0, 0, fmt.Errorf("ULEB128: unexpected end of data")
		}
		b := data[off+i]
		result |= uint64(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			return result, i + 1, nil
		}
		if shift >= 64 {
			return 0, 0, fmt.Errorf("ULEB128: overflow")
		}
	}
}

// readSLEB128 decodes a signed LEB128 integer starting at off.
func readSLEB128(data []byte, off int) (int64, int, error) {
	var result int64
	var shift uint
	for i := 0; ; i++ {
		if off+i >= len(data) {
			return 0, 0, fmt.Errorf("SLEB128: unexpected end of data")
		}
		b := data[off+i]
		result |= int64(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			// Sign extend if necessary
			if shift < 64 && (b&0x40) != 0 {
				result |= -(1 << shift)
			}
			return result, i + 1, nil
		}
		if shift >= 64 {
			return 0, 0, fmt.Errorf("SLEB128: overflow")
		}
	}
}

// appendULEB128 encodes v as unsigned LEB128 and appends to buf.
func appendULEB128(buf []byte, v uint64) []byte {
	for {
		b := uint8(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	return buf
}

// appendSLEB128 encodes v as signed LEB128 and appends to buf.
func appendSLEB128(buf []byte, v int64) []byte {
	more := true
	for more {
		b := uint8(v & 0x7F)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			more = false
		} else {
			b |= 0x80
		}
		buf = append(buf, b)
	}
	return buf
}

// uleb128Size returns the number of bytes needed to encode v as ULEB128.
func uleb128Size(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}