package pe

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func parseDLL(name string, data []byte) (lib *SharedLib, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%s: DLL parse panic: %v", name, p)
		}
	}()

	if len(data) < sizeDOSStub {
		return nil, fmt.Errorf("%s: too small for PE header", name)
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return nil, fmt.Errorf("%s: not a PE file (no MZ signature)", name)
	}

	r := newReader(data, name)
	r.seek(0x3C)
	peOff := int(r.u32())

	if peOff+sizePESig+sizeCOFFHdr > len(data) {
		return nil, fmt.Errorf("%s: PE offset 0x%x out of bounds", name, peOff)
	}
	r.seek(peOff)
	sig := r.bytes(4)
	if sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0 {
		return nil, fmt.Errorf("%s: bad PE signature", name)
	}

	machine   := r.u16()
	nSections := int(r.u16())
	r.skip(4 + 4 + 4)
	optSize   := int(r.u16())
	r.skip(2)

	if machine != imageMachineAMD64 && machine != imageMachineARM64 {
		return nil, fmt.Errorf("%s: unsupported machine 0x%04X", name, machine)
	}

	optStart := r.pos()
	if optSize < 2 {
		return nil, fmt.Errorf("%s: optional header too small (%d)", name, optSize)
	}
	magic := r.u16()
	if magic != imageNTOptionalHdr64Magic {
		return nil, fmt.Errorf("%s: not PE32+ (magic=0x%04X)", name, magic)
	}
	r.skip(22)
	imageBase := r.u64()
	r.skip(4 + 4)
	r.skip(2+2+2+2+2+2)
	r.skip(4 + 4 + 4 + 4)
	r.skip(2 + 2)
	r.skip(8+8+8+8)
	r.skip(4)
	numDirs := int(r.u32())
	_ = optStart

	type dataDir struct{ rva, size uint32 }
	dirs := make([]dataDir, numDirs)
	for i := range dirs {
		dirs[i].rva  = r.u32()
		dirs[i].size = r.u32()
	}

	r.seek(peOff + sizePESig + sizeCOFFHdr + optSize)
	type secHdr struct {
		name    string
		vsize   uint32
		vaddr   uint32
		rawSize uint32
		rawOff  uint32
	}
	shdrs := make([]secHdr, nSections)
	for i := range shdrs {
		nb := r.bytes(8)
		shdrs[i] = secHdr{
			name:    strings.TrimRight(string(nb), "\x00"),
			vsize:   r.u32(),
			vaddr:   r.u32(),
			rawSize: r.u32(),
			rawOff:  r.u32(),
		}
		r.skip(4 + 4 + 2 + 2 + 4)
	}

	rvaToOff := func(rva uint32) (int, bool) {
		for _, sh := range shdrs {
			if rva >= sh.vaddr && rva < sh.vaddr+sh.vsize {
				return int(sh.rawOff) + int(rva-sh.vaddr), true
			}
		}
		return 0, false
	}

	readCStr := func(off int) string {
		start := off
		for off < len(data) && data[off] != 0 {
			off++
		}
		return string(data[start:off])
	}

	soname := name
	if numDirs > dirExport && dirs[dirExport].rva != 0 {
		if eoff, ok := rvaToOff(dirs[dirExport].rva); ok && eoff+40 <= len(data) {
			nameRVA := binary.LittleEndian.Uint32(data[eoff+12:])
			if noff, ok := rvaToOff(nameRVA); ok {
				soname = readCStr(noff)
			}
		}
	}

	exports := make(map[string]*SharedExport)
	if numDirs > dirExport && dirs[dirExport].rva != 0 {
		eoff, ok := rvaToOff(dirs[dirExport].rva)
		if ok && eoff+40 <= len(data) {
			ordBase      := binary.LittleEndian.Uint32(data[eoff+16:])
			nFuncs       := int(binary.LittleEndian.Uint32(data[eoff+20:]))
			nNames       := int(binary.LittleEndian.Uint32(data[eoff+24:]))
			rvaFuncs     := binary.LittleEndian.Uint32(data[eoff+28:])
			rvaNames     := binary.LittleEndian.Uint32(data[eoff+32:])
			rvaOrdinals  := binary.LittleEndian.Uint32(data[eoff+36:])

			funcsOff, funcsOK   := rvaToOff(rvaFuncs)
			namesOff, namesOK   := rvaToOff(rvaNames)
			ordinalsOff, ordsOK := rvaToOff(rvaOrdinals)

			if funcsOK && namesOK && ordsOK {
				for i := 0; i < nNames; i++ {
					if namesOff+i*4+4 > len(data) {
						break
					}
					nRVA := binary.LittleEndian.Uint32(data[namesOff+i*4:])
					noff, ok := rvaToOff(nRVA)
					if !ok {
						continue
					}
					fnName := readCStr(noff)

					if ordinalsOff+i*2+2 > len(data) {
						break
					}
					ordIdx := int(binary.LittleEndian.Uint16(data[ordinalsOff+i*2:]))
					if ordIdx >= nFuncs || funcsOff+ordIdx*4+4 > len(data) {
						continue
					}
					fnRVA := binary.LittleEndian.Uint32(data[funcsOff+ordIdx*4:])
					exports[fnName] = &SharedExport{
						Name:    fnName,
						Value:   imageBase + uint64(fnRVA),
						Binding: BindGlobal,
						Type:    SymTypeFunc,
						Version: fmt.Sprintf("@%d", int(ordBase)+ordIdx),
					}
				}
			}
			_ = nFuncs
		}
	}

	var needed []string
	if numDirs > dirImport && dirs[dirImport].rva != 0 {
		ioff, ok := rvaToOff(dirs[dirImport].rva)
		if ok {
			for {
				if ioff+sizeImportDesc > len(data) {
					break
				}
				nameRVA := binary.LittleEndian.Uint32(data[ioff+12:])
				if nameRVA == 0 {
					break
				}
				if noff, ok2 := rvaToOff(nameRVA); ok2 {
					needed = append(needed, readCStr(noff))
				}
				ioff += sizeImportDesc
			}
		}
	}

	return &SharedLib{
		Name:    name,
		Soname:  soname,
		Needed:  needed,
		Rpaths:  nil,
		Exports: exports,
	}, nil
}