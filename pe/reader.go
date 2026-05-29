package pe

import (
	"encoding/binary"
	"fmt"
)

type leReader struct {
	data []byte
	off  int
	name string
}

func newReader(data []byte, name string) *leReader {
	return &leReader{data: data, name: name}
}

func (r *leReader) pos() int { return r.off }

func (r *leReader) seek(off int) {
	if off < 0 || off > len(r.data) {
		panic(fmt.Sprintf("%s: seek to %d out of bounds (len=%d)", r.name, off, len(r.data)))
	}
	r.off = off
}

func (r *leReader) need(n int) {
	if r.off+n > len(r.data) {
		panic(fmt.Sprintf("%s: read %d bytes at offset %d out of bounds (len=%d)",
			r.name, n, r.off, len(r.data)))
	}
}

func (r *leReader) u8() uint8 {
	r.need(1)
	v := r.data[r.off]
	r.off++
	return v
}

func (r *leReader) u16() uint16 {
	r.need(2)
	v := binary.LittleEndian.Uint16(r.data[r.off:])
	r.off += 2
	return v
}

func (r *leReader) u32() uint32 {
	r.need(4)
	v := binary.LittleEndian.Uint32(r.data[r.off:])
	r.off += 4
	return v
}

func (r *leReader) u64() uint64 {
	r.need(8)
	v := binary.LittleEndian.Uint64(r.data[r.off:])
	r.off += 8
	return v
}

func (r *leReader) bytes(n int) []byte {
	r.need(n)
	b := r.data[r.off : r.off+n]
	r.off += n
	return b
}

func (r *leReader) skip(n int) {
	r.need(n)
	r.off += n
}

func safeRead(fn func()) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%v", p)
		}
	}()
	fn()
	return nil
}