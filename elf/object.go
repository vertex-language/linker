// object.go — ELF64 ET_REL parser producing *Object.
package elf

import "fmt"

// ParseObject parses an ELF64 ET_REL relocatable object from raw bytes
// and returns a normalised *Object.
func parseObject(name string, data []byte, targetArch Arch) (*Object, error) {
	r := newReader(data, name)

	magic, err := r.U32(0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if magic != MH_MAGIC_64 {
		return nil, fmt.Errorf("%s: unsupported Mach-O magic 0x%X (expected 64-bit LE)", name, magic)
	}

	cpuType, err := r.I32(4)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	fileType, err := r.U32(12)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if fileType != MH_OBJECT {
		return nil, fmt.Errorf("%s: expected MH_OBJECT, got filetype 0x%X", name, fileType)
	}

	ncmds, err := r.U32(16)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	var machine uint16
	switch cpuType {
	case CPU_TYPE_AMD64:
		machine = 0x3E // EM_X86_64
	case CPU_TYPE_ARM64:
		machine = 0xB7 // EM_AARCH64
	}

	obj := &Object{
		Name:     name,
		Machine:  machine,
		Sections: []*ObjectSection{nil},
		Symbols:  []*ObjectSymbol{nil},
	}

	type rawSection struct {
		segname   string
		sectname  string
		addr      uint64
		size      uint64
		offset    uint32
		align     uint32
		reloff    uint32
		nreloc    uint32
		flags     uint32
		reserved1 uint32
		reserved2 uint32
		idx       int
	}

	var sections []rawSection
	var symoff, nsyms, stroff, strsize uint32

	pos := machHeaderSize64
	for i := uint32(0); i < ncmds; i++ {
		cmd, err := r.U32(pos)
		if err != nil {
			return nil, fmt.Errorf("%s: lc[%d] cmd: %w", name, i, err)
		}
		cmdsize, err := r.U32(pos + 4)
		if err != nil {
			return nil, fmt.Errorf("%s: lc[%d] cmdsize: %w", name, i, err)
		}
		if cmdsize < 8 {
			return nil, fmt.Errorf("%s: lc[%d] invalid cmdsize %d", name, i, cmdsize)
		}

		switch cmd {
		case LC_SEGMENT_64:
			if int(cmdsize) < segCmdSize64 {
				break
			}
			nsects, _ := r.U32(pos + 64)
			secOff := pos + segCmdSize64
			for s := uint32(0); s < nsects; s++ {
				if secOff+sectSize64 > pos+int(cmdsize) {
					break
				}
				sectname, _ := r.FixedString(secOff, 16)
				seg2, _ := r.FixedString(secOff+16, 16)
				addr, _ := r.U64(secOff + 32)
				size, _ := r.U64(secOff + 40)
				offset, _ := r.U32(secOff + 48)
				align, _ := r.U32(secOff + 52)
				reloff, _ := r.U32(secOff + 56)
				nreloc, _ := r.U32(secOff + 60)
				flags, _ := r.U32(secOff + 64)
				reserved1, _ := r.U32(secOff + 68)
				reserved2, _ := r.U32(secOff + 72)
				sections = append(sections, rawSection{
					segname:   strings.TrimRight(seg2, "\x00"),
					sectname:  strings.TrimRight(sectname, "\x00"),
					addr:      addr, size: size,
					offset: offset, align: align,
					reloff: reloff, nreloc: nreloc,
					flags:     flags,
					reserved1: reserved1, reserved2: reserved2,
					idx: len(sections) + 1,
				})
				secOff += sectSize64
			}

		case LC_SYMTAB:
			symoff, _ = r.U32(pos + 8)
			nsyms, _ = r.U32(pos + 12)
			stroff, _ = r.U32(pos + 16)
			strsize, _ = r.U32(pos + 20)
		}

		pos += int(cmdsize)
	}

	// ── Build ObjectSection list ──────────────────────────────────────────────

	skipSection := func(seg, sect string, flags uint32) bool {
		if seg+"/"+sect == "__TEXT/__eh_frame" {
			return false
		}
		stype := flags & 0xFF
		return stype == S_SYMBOL_STUBS ||
			stype == S_NON_LAZY_SYMBOL_POINTERS ||
			stype == S_LAZY_SYMBOL_POINTERS
	}

	for _, s := range sections {
		elfName := machoToELFSection(s.segname, s.sectname)
		sflags := machoSectionFlags(s.segname, s.flags)
		skip := skipSection(s.segname, s.sectname, s.flags)

		var secData []byte
		if sflags&SecBSS == 0 && s.size > 0 && s.offset > 0 {
			end := int(s.offset) + int(s.size)
			if end <= len(data) {
				secData = make([]byte, s.size)
				copy(secData, data[s.offset:end])
			}
		}

		align := uint64(1)
		if s.align <= 30 {
			align = 1 << s.align
		}

		obj.Sections = append(obj.Sections, &ObjectSection{
			Name:     elfName,
			Flags:    sflags,
			Data:     secData,
			Size:     s.size,
			Align:    align,
			RawType:  s.flags & 0xFF,
			RawFlags: uint64(s.flags),
			Index:    s.idx,
			Skip:     skip,
		})
	}

	// ── Parse symbol table ────────────────────────────────────────────────────

	if nsyms > 0 && symoff > 0 && stroff > 0 {
		for i := uint32(0); i < nsyms; i++ {
			soff := int(symoff) + int(i)*nlist64Size
			strx, err := r.U32(soff)
			if err != nil {
				break
			}
			ntype, _ := r.U8(soff + 4)
			nsect, _ := r.U8(soff + 5)
			ndesc, _ := r.U16(soff + 6)
			nvalue, _ := r.U64(soff + 8)

			if ntype&N_STAB != 0 {
				obj.Symbols = append(obj.Symbols, nil)
				continue
			}

			symName := ""
			if strx < strsize {
				symName, _ = r.CString(int(stroff)+int(strx), int(strsize-strx))
			}

			binding := BindLocal
			if ntype&N_EXT != 0 {
				binding = BindGlobal
			}
			if ndesc&N_WEAK_REF != 0 || ndesc&N_WEAK_DEF != 0 {
				binding = BindWeak
			}

			symType := ntype & N_TYPE
			sectionIdx := SymSecUndef
			sectionName := ""

			switch symType {
			case N_UNDF:
				sectionIdx = SymSecUndef
			case N_ABS:
				sectionIdx = SymSecAbs
				sectionName = "*ABS*"
			case N_SECT:
				if nsect > 0 && int(nsect) <= len(sections) {
					s := sections[nsect-1]
					sectionIdx = int(nsect)
					sectionName = machoToELFSection(s.segname, s.sectname)
				}
			default:
				obj.Symbols = append(obj.Symbols, nil)
				continue
			}

			obj.Symbols = append(obj.Symbols, &ObjectSymbol{
				Name:        symName,
				Value:       nvalue,
				Binding:     binding,
				SectionIdx:  sectionIdx,
				SectionName: sectionName,
			})
		}
	}

	// ── Parse relocations ─────────────────────────────────────────────────────

	for _, s := range sections {
		if s.nreloc == 0 || s.reloff == 0 {
			continue
		}

		var secData []byte
		if s.offset > 0 && s.size > 0 {
			end := int(s.offset) + int(s.size)
			if end <= len(data) {
				secData = data[s.offset:end]
			}
		}

		var pendingAddend int64
		hasPending := false

		for j := uint32(0); j < s.nreloc; j++ {
			roff := int(s.reloff) + int(j)*relocEntrySize
			if roff+8 > len(data) {
				break
			}
			raddr := int32(binary.LittleEndian.Uint32(data[roff:]))
			rinfo := binary.LittleEndian.Uint32(data[roff+4:])

			symnum := rinfo & 0xFFFFFF
			pcrel := (rinfo >> 24) & 0x1
			rlen := (rinfo >> 25) & 0x3
			extern := (rinfo >> 27) & 0x1
			rtype := (rinfo >> 28) & 0xF

			if cpuType == CPU_TYPE_ARM64 && rtype == ARM64_RELOC_ADDEND {
				pendingAddend = int64(int32(symnum))
				hasPending = true
				continue
			}

			// ARM64 instruction relocations encode nothing useful in the
			// instruction word — the assembler leaves placeholder bits that
			// must not be interpreted as an addend. Only ARM64_RELOC_UNSIGNED
			// (absolute data pointer) actually stores an addend in the bytes.
			// AMD64 PC-relative relocs store −4 (next-instruction bias) which
			// the patch functions expect, so we always read those.
			isARM64InstrReloc := cpuType == CPU_TYPE_ARM64 &&
				rtype != ARM64_RELOC_UNSIGNED

			addend := int64(0)
			if !isARM64InstrReloc && int(raddr) < len(secData) {
				switch rlen {
				case 2:
					if int(raddr)+4 <= len(secData) {
						addend = int64(int32(binary.LittleEndian.Uint32(secData[raddr:])))
					}
				case 3:
					if int(raddr)+8 <= len(secData) {
						addend = int64(binary.LittleEndian.Uint64(secData[raddr:]))
					}
				}
			}
			if hasPending {
				addend += pendingAddend
				hasPending = false
			}

			symIdx := uint32(0)
			if extern != 0 {
				symIdx = symnum + 1
			}

			packedType := rtype | (rlen << 8) | (pcrel << 16)
			obj.Relocs = append(obj.Relocs, &ObjectReloc{
				TargetSectionIdx: s.idx,
				Offset:           uint64(raddr),
				SymIdx:           symIdx,
				Type:             packedType,
				Addend:           addend,
			})
		}
	}

	return obj, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func elfSectionFlags(shType uint32, shFlags uint64) SectionFlags {
	var f SectionFlags
	if shFlags&SHF_ALLOC != 0 {
		f |= SecAlloc
	}
	if shFlags&SHF_WRITE != 0 {
		f |= SecWrite
	}
	if shFlags&SHF_EXECINSTR != 0 {
		f |= SecExec
	}
	if shFlags&SHF_TLS != 0 {
		f |= SecTLS
	}
	if shType == shtNobits {
		f |= SecBSS
	}
	return f
}

func isLinkerInternalSection(shType uint32) bool {
	switch shType {
	case shtSymtab, shtStrtab, shtRela, shtGroup, SHT_REL:
		return true
	}
	return false
}

func elfBinding(b uint8) SymBinding {
	switch b {
	case STB_GLOBAL:
		return BindGlobal
	case STB_WEAK:
		return BindWeak
	default:
		return BindLocal
	}
}

func elfSymType(t uint8) SymType {
	switch t {
	case STT_OBJECT:
		return SymTypeObject
	case STT_FUNC:
		return SymTypeFunc
	case STT_SECTION:
		return SymTypeSection
	case STT_FILE:
		return SymTypeFile
	case STT_TLS:
		return SymTypeTLS
	default:
		return SymTypeNone
	}
}