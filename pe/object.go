package pe

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func parseObject(name string, data []byte) (obj *Object, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%s: COFF parse panic: %v", name, p)
		}
	}()

	if len(data) < sizeCOFFHdr {
		return nil, fmt.Errorf("%s: too small for COFF header", name)
	}

	r := newReader(data, name)

	machine   := r.u16()
	nSections := int(r.u16())
	r.skip(4)
	symOff    := r.u32()
	nSyms     := int(r.u32())
	optSize   := int(r.u16())
	r.skip(2)

	if machine != imageMachineAMD64 && machine != imageMachineARM64 {
		return nil, fmt.Errorf("%s: unsupported COFF machine 0x%04X", name, machine)
	}
	r.skip(optSize)

	var strtab []byte
	if symOff > 0 && nSyms >= 0 {
		stOff := int(symOff) + nSyms*18
		if stOff+4 <= len(data) {
			stSize := int(binary.LittleEndian.Uint32(data[stOff:]))
			if stSize >= 4 && stOff+stSize <= len(data) {
				strtab = data[stOff : stOff+stSize]
			}
		}
	}

	type rawSec struct {
		name     string
		vsize    uint32
		vaddr    uint32
		rawSize  uint32
		rawOff   uint32
		relocOff uint32
		nRelocs  uint16
		ch       uint32
	}
	raws := make([]rawSec, nSections)
	for i := range raws {
		nb := r.bytes(8)
		raws[i] = rawSec{
			name:     coffSecName(nb, strtab),
			vsize:    r.u32(),
			vaddr:    r.u32(),
			rawSize:  r.u32(),
			rawOff:   r.u32(),
			relocOff: r.u32(),
		}
		r.skip(4)
		raws[i].nRelocs = r.u16()
		r.skip(2)
		raws[i].ch = r.u32()
	}

	sections := make([]*ObjectSection, nSections+1)
	for i, rs := range raws {
		isBSS := rs.ch&imageSCNCntUninitializedData != 0
		skip   := coffSkipSection(rs.name, rs.ch)

		var secData []byte
		if !isBSS && rs.rawSize > 0 && !skip {
			end := int(rs.rawOff) + int(rs.rawSize)
			if int(rs.rawOff) < 0 || end > len(data) {
				return nil, fmt.Errorf("%s: section %q raw data out of bounds", name, rs.name)
			}
			secData = make([]byte, rs.rawSize)
			copy(secData, data[rs.rawOff:end])
		}

		size := uint64(rs.rawSize)
		if isBSS {
			size = uint64(rs.vsize)
			if size == 0 {
				size = uint64(rs.rawSize)
			}
		}

		sections[i+1] = &ObjectSection{
			Name:     rs.name,
			Flags:    coffSecFlags(rs.ch),
			Data:     secData,
			Size:     size,
			Align:    coffSecAlign(rs.ch),
			RawType:  0,
			RawFlags: uint64(rs.ch),
			Index:    i + 1,
			Skip:     skip,
		}
	}

	syms := []*ObjectSymbol{nil}
	for i := 0; i < nSyms; {
		base := int(symOff) + i*18
		if base+18 > len(data) {
			break
		}
		sym := coffParseSymbol(data[base:base+18], strtab, sections, i)
		syms = append(syms, sym)
		i++
		nAux := int(data[base+17])
		for j := 0; j < nAux; j++ {
			syms = append(syms, nil)
			i++
		}
	}

	var relocs []*ObjectReloc
	for si, rs := range raws {
		if rs.nRelocs == 0 || rs.relocOff == 0 {
			continue
		}
		if sections[si+1] == nil || sections[si+1].Skip {
			continue
		}
		for j := 0; j < int(rs.nRelocs); j++ {
			off := int(rs.relocOff) + j*10
			if off+10 > len(data) {
				break
			}
			rOff  := binary.LittleEndian.Uint32(data[off:])
			rSym  := binary.LittleEndian.Uint32(data[off+4:])
			rType := binary.LittleEndian.Uint16(data[off+8:])

			var addend int64
			sec := sections[si+1]
			if sec != nil && sec.Data != nil {
				addend = coffReadAddend(sec.Data, int(rOff), uint32(rType), machine)
			}

			relocs = append(relocs, &ObjectReloc{
				TargetSectionIdx: si + 1,
				Offset:           uint64(rOff),
				SymIdx:           rSym + 1,
				Type:             uint32(rType),
				Addend:           addend,
			})
		}
	}

	return &Object{
		Name:     name,
		Machine:  machine,
		Sections: sections,
		Symbols:  syms,
		Relocs:   relocs,
	}, nil
}

func coffSecName(b []byte, strtab []byte) string {
	if b[0] == '/' {
		offStr := strings.TrimRight(string(b[1:]), "\x00 ")
		var off int
		fmt.Sscanf(offStr, "%d", &off)
		if strtab != nil && off >= 4 && off < len(strtab) {
			end := off
			for end < len(strtab) && strtab[end] != 0 {
				end++
			}
			return string(strtab[off:end])
		}
	}
	s := string(b[:8])
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, " ")
}

func coffParseSymbol(b []byte, strtab []byte, sections []*ObjectSection, symIdx int) *ObjectSymbol {
	var symName string
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
		off := int(binary.LittleEndian.Uint32(b[4:8]))
		if strtab != nil && off >= 4 && off < len(strtab) {
			end := off
			for end < len(strtab) && strtab[end] != 0 {
				end++
			}
			symName = string(strtab[off:end])
		}
	} else {
		s := string(b[:8])
		if i := strings.IndexByte(s, 0); i >= 0 {
			s = s[:i]
		}
		symName = s
	}

	value        := binary.LittleEndian.Uint32(b[8:12])
	secNumRaw    := binary.LittleEndian.Uint16(b[12:14])
	symType      := b[14]
	storageClass := b[16]

	var binding SymBinding
	switch storageClass {
	case symClassExternal:
		binding = BindGlobal
	case symClassWeakExternal:
		binding = BindWeak
	default:
		binding = BindLocal
	}

	var sType SymType
	if symType == 0x20 {
		sType = SymTypeFunc
	}

	var secIdx int
	var secName string

	switch secNumRaw {
	case 0:
		if binding == BindGlobal && value > 0 {
			secIdx  = SymSecCommon
			secName = ""
		} else {
			secIdx  = SymSecUndef
			secName = ""
		}
	case 0xFFFF:
		secIdx  = SymSecAbs
		secName = "*ABS*"
	case 0xFFFE:
		secIdx  = SymSecUndef
		secName = ""
	default:
		sn := int(secNumRaw)
		if sn > 0 && sn < len(sections) && sections[sn] != nil {
			secIdx  = sn
			secName = sections[sn].Name
		}
	}

	return &ObjectSymbol{
		Name:        symName,
		Value:       uint64(value),
		Binding:     binding,
		Type:        sType,
		SectionIdx:  secIdx,
		SectionName: secName,
	}
}

func coffSecFlags(ch uint32) SectionFlags {
	var f SectionFlags
	if ch&(imageSCNMemExecute|imageSCNMemRead|imageSCNMemWrite) != 0 {
		f |= SecAlloc
	}
	if ch&imageSCNMemExecute != 0 {
		f |= SecExec
	}
	if ch&imageSCNMemWrite != 0 {
		f |= SecWrite
	}
	if ch&imageSCNCntUninitializedData != 0 {
		f |= SecBSS
	}
	return f
}

func coffSecAlign(ch uint32) uint64 {
	field := (ch >> 20) & 0xF
	if field == 0 {
		return 16
	}
	return 1 << (field - 1)
}

func coffSkipSection(name string, ch uint32) bool {
	if ch&imageSCNLnkInfo != 0 || ch&imageSCNLnkRemove != 0 {
		return true
	}
	switch name {
	case ".drectve", ".llvm_addrsig", ".llvm.call-graph-profile":
		return true
	}
	return false
}

func coffReadAddend(data []byte, off int, relType uint32, machine uint16) int64 {
	switch relType {
	case relAMD64Addr64, relARM64Addr64:
		if off+8 <= len(data) {
			v := int64(binary.LittleEndian.Uint64(data[off:]))
			binary.LittleEndian.PutUint64(data[off:], 0)
			return v
		}
	case relAMD64Addr32, relAMD64Addr32NB,
		relAMD64Rel32, relAMD64Rel32_1, relAMD64Rel32_2,
		relAMD64Rel32_3, relAMD64Rel32_4, relAMD64Rel32_5,
		relAMD64SecRel,
		relARM64Addr32, relARM64Addr32NB, relARM64SecRel, relARM64Rel32:
		if off+4 <= len(data) {
			v := int32(binary.LittleEndian.Uint32(data[off:]))
			binary.LittleEndian.PutUint32(data[off:], 0)
			return int64(v)
		}
	}
	return 0
}