package codesign

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Mach-O magic numbers.
const (
	mhMagic64 uint32 = 0xfeedfacf // 64-bit, host-endian
	mhCigam64 uint32 = 0xcffaedfe // 64-bit, byte-swapped
	fatMagic  uint32 = 0xcafebabe // universal header (big-endian on disk)
	fatCigam  uint32 = 0xbebafeca
)

// Mach-O filetypes we care about.
const (
	mhExecute uint32 = 0x2
	mhDylib   uint32 = 0x6
	mhBundle  uint32 = 0x8
)

// Load command numbers.
const (
	lcSegment64      uint32 = 0x19
	lcCodeSignature  uint32 = 0x1d
	lcReqDyld        uint32 = 0x80000000
)

// Slice is one architecture inside a (possibly fat) Mach-O image. For a thin
// file there is exactly one Slice covering the whole image.
type Slice struct {
	Offset    int64  // file offset of this slice within the outer image
	Size      int64  // size of this slice
	CPU       uint32 // cputype
	SubCPU    uint32 // cpusubtype
	Bytes     []byte // the slice's bytes (a sub-slice of the parent image)
	bigEndian bool

	header    machHeader
	loadCmds  []loadCmd
	textOff   int64 // __TEXT fileoff (execSegBase)
	textSize  int64 // __TEXT filesize (execSegLimit)
	linkEdit  *segment64
	csCmd     *loadCmd // existing LC_CODE_SIGNATURE, if any
	isMain    bool
}

type machHeader struct {
	Magic      uint32
	CPU        uint32
	SubCPU     uint32
	FileType   uint32
	NCmds      uint32
	SizeOfCmds uint32
	Flags      uint32
	Reserved   uint32
}

type loadCmd struct {
	Cmd    uint32
	Size   uint32
	Offset int64 // offset of this command within the slice
}

type segment64 struct {
	Name     string
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	cmdOff   int64 // offset of the LC_SEGMENT_64 within the slice
}

// Image is a parsed Mach-O file: one or more architecture slices.
type Image struct {
	raw    []byte
	isFat  bool
	Slices []*Slice
}

func (s *Slice) order() binary.ByteOrder {
	if s.bigEndian {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Parse reads a Mach-O image (fat or thin) from raw bytes without copying the
// backing array; edits later operate in place on a grown copy.
func Parse(raw []byte) (*Image, error) {
	if len(raw) < 4 {
		return nil, errors.New("codesign: file too small")
	}
	magic := binary.BigEndian.Uint32(raw[:4])
	img := &Image{raw: raw}

	switch magic {
	case fatMagic, fatCigam:
		img.isFat = true
		if err := img.parseFat(raw); err != nil {
			return nil, err
		}
	default:
		sl, err := parseThin(raw, 0, int64(len(raw)))
		if err != nil {
			return nil, err
		}
		img.Slices = []*Slice{sl}
	}
	return img, nil
}

func (img *Image) parseFat(raw []byte) error {
	// fat_header: magic(4) + nfat_arch(4), both big-endian.
	if len(raw) < 8 {
		return errors.New("codesign: truncated fat header")
	}
	n := binary.BigEndian.Uint32(raw[4:8])
	const fatArchSize = 20 // cputype,cpusubtype,offset,size,align (5×uint32)
	off := 8
	for i := uint32(0); i < n; i++ {
		if off+fatArchSize > len(raw) {
			return errors.New("codesign: truncated fat_arch table")
		}
		cpu := binary.BigEndian.Uint32(raw[off:])
		sub := binary.BigEndian.Uint32(raw[off+4:])
		fo := int64(binary.BigEndian.Uint32(raw[off+8:]))
		fs := int64(binary.BigEndian.Uint32(raw[off+12:]))
		off += fatArchSize
		if fo+fs > int64(len(raw)) {
			return fmt.Errorf("codesign: fat slice %d out of range", i)
		}
		sl, err := parseThin(raw[fo:fo+fs], fo, fs)
		if err != nil {
			return fmt.Errorf("codesign: slice %d: %w", i, err)
		}
		sl.CPU, sl.SubCPU = cpu, sub
		img.Slices = append(img.Slices, sl)
	}
	return nil
}

func parseThin(b []byte, fileOff, size int64) (*Slice, error) {
	if len(b) < 32 {
		return nil, errors.New("codesign: truncated mach header")
	}
	magic := binary.LittleEndian.Uint32(b[:4])
	var bo binary.ByteOrder
	switch magic {
	case mhMagic64:
		bo = binary.LittleEndian
	case mhCigam64:
		bo = binary.BigEndian
	default:
		// Re-read big-endian to give a clearer message for 32-bit/other.
		return nil, fmt.Errorf("codesign: unsupported magic 0x%08x (only 64-bit Mach-O supported)", binary.BigEndian.Uint32(b[:4]))
	}

	sl := &Slice{Offset: fileOff, Size: size, Bytes: b, bigEndian: bo == binary.BigEndian}
	h := &sl.header
	h.Magic = magic
	h.CPU = bo.Uint32(b[4:])
	h.SubCPU = bo.Uint32(b[8:])
	h.FileType = bo.Uint32(b[12:])
	h.NCmds = bo.Uint32(b[16:])
	h.SizeOfCmds = bo.Uint32(b[20:])
	h.Flags = bo.Uint32(b[24:])
	sl.CPU, sl.SubCPU = h.CPU, h.SubCPU
	sl.isMain = h.FileType == mhExecute

	const machHeader64Size = 32
	off := int64(machHeader64Size)
	for i := uint32(0); i < h.NCmds; i++ {
		if off+8 > int64(len(b)) {
			return nil, errors.New("codesign: load command past end of slice")
		}
		cmd := bo.Uint32(b[off:])
		csize := bo.Uint32(b[off+4:])
		if csize < 8 || off+int64(csize) > int64(len(b)) {
			return nil, fmt.Errorf("codesign: bad load command size %d", csize)
		}
		lc := loadCmd{Cmd: cmd, Size: csize, Offset: off}
		sl.loadCmds = append(sl.loadCmds, lc)

		switch cmd {
		case lcSegment64:
			seg := parseSegment64(b[off:off+int64(csize)], bo, off)
			switch seg.Name {
			case "__TEXT":
				sl.textOff = int64(seg.FileOff)
				sl.textSize = int64(seg.FileSize)
			case "__LINKEDIT":
				s := seg
				sl.linkEdit = &s
			}
		case lcCodeSignature:
			c := sl.loadCmds[len(sl.loadCmds)-1]
			sl.csCmd = &c
		}
		off += int64(csize)
	}
	if sl.linkEdit == nil {
		return nil, errors.New("codesign: no __LINKEDIT segment")
	}
	return sl, nil
}

func parseSegment64(b []byte, bo binary.ByteOrder, cmdOff int64) segment64 {
	// segment_command_64: cmd,cmdsize,segname[16],vmaddr,vmsize,fileoff,filesize,...
	name := cstr(b[8:24])
	return segment64{
		Name:     name,
		VMAddr:   bo.Uint64(b[24:]),
		VMSize:   bo.Uint64(b[32:]),
		FileOff:  bo.Uint64(b[40:]),
		FileSize: bo.Uint64(b[48:]),
		cmdOff:   cmdOff,
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// signatureRegionStart returns the file offset (within the slice) at which the
// signature data must begin: just past the end of all non-signature content.
// That is the codeLimit for the CodeDirectory.
func (s *Slice) signatureRegionStart() int64 {
	// Signature always sits at the very end of __LINKEDIT, which is the end of
	// the slice. If a signature already exists, its dataoff marks the start;
	// otherwise it's the current end of __LINKEDIT.
	if s.csCmd != nil {
		bo := s.order()
		// linkedit_data_command: cmd,cmdsize,dataoff,datasize
		return int64(bo.Uint32(s.Bytes[s.csCmd.Offset+8:]))
	}
	return int64(s.linkEdit.FileOff + s.linkEdit.FileSize)
}

// hasReservedSignatureSpace reports whether an LC_CODE_SIGNATURE is already
// present. Inserting a new one into a binary that lacks it requires shifting
// content and is not supported here (matches codesign_allocate's job, which
// the linker normally performs).
func (s *Slice) hasReservedSignatureSpace() bool { return s.csCmd != nil }