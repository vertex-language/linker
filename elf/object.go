// object.go — ELF64 ET_REL parser producing *linker.Object.
package elf

import (
	"fmt"

	"github.com/vertex-language/linker"
)

// ParseObject parses an ELF64 ET_REL relocatable object from raw bytes
// and returns a normalised *linker.Object.
func ParseObject(name string, data []byte) (*linker.Object, error) {
	r := newReader(data)

	if len(data) < ehdrSize {
		return nil, fmt.Errorf("object %q: file too small", name)
	}
	if string(data[0:4]) != "\x7fELF" {
		return nil, fmt.Errorf("object %q: bad ELF magic", name)
	}
	if data[EI_CLASS] != elfClass64 {
		return nil, fmt.Errorf("object %q: not ELF64", name)
	}
	if data[EI_DATA] != elfData2LSB {
		return nil, fmt.Errorf("object %q: only little-endian supported", name)
	}

	eType, _ := r.u16(ehoff_type)
	if eType != etRel {
		return nil, fmt.Errorf("object %q: not ET_REL (e_type=%d)", name, eType)
	}

	machine, _ := r.u16(ehoff_machine)
	eflags, _ := r.u32(ehoff_flags)
	shoff, _ := r.u64(ehoff_shoff)
	shentsize, _ := r.u16(ehoff_shentsize)
	shnum, _ := r.u16(ehoff_shnum)
	shstrndx, _ := r.u16(ehoff_shstrndx)

	if uint64(shentsize) < shdrSize {
		return nil, fmt.Errorf("object %q: e_shentsize=%d too small", name, shentsize)
	}

	// ── Section headers ───────────────────────────────────────────────────────

	type shdrRaw struct {
		nameOff, stype uint32
		flags          uint64
		addr, offset   uint64
		size           uint64
		link, info     uint32
		align, entsize uint64
	}

	readShdr := func(i int) (shdrRaw, error) {
		base := int(shoff) + i*int(shentsize)
		var s shdrRaw
		var err error
		if s.nameOff, err = r.u32(base + shoff_name); err != nil { return s, err }
		if s.stype, err   = r.u32(base + shoff_type); err != nil { return s, err }
		if s.flags, err   = r.u64(base + shoff_flags); err != nil { return s, err }
		if s.addr, err    = r.u64(base + shoff_addr); err != nil { return s, err }
		if s.offset, err  = r.u64(base + shoff_offset); err != nil { return s, err }
		if s.size, err    = r.u64(base + shoff_size); err != nil { return s, err }
		if s.link, err    = r.u32(base + shoff_link); err != nil { return s, err }
		if s.info, err    = r.u32(base + shoff_info); err != nil { return s, err }
		if s.align, err   = r.u64(base + shoff_addralign); err != nil { return s, err }
		if s.entsize, err = r.u64(base + shoff_entsize); err != nil { return s, err }
		return s, nil
	}

	shdrs := make([]shdrRaw, shnum)
	for i := range shdrs {
		sh, err := readShdr(i)
		if err != nil {
			return nil, fmt.Errorf("object %q: shdr %d: %w", name, i, err)
		}
		shdrs[i] = sh
	}

	// ── .shstrtab ─────────────────────────────────────────────────────────────

	if int(shstrndx) >= len(shdrs) {
		return nil, fmt.Errorf("object %q: e_shstrndx=%d out of range", name, shstrndx)
	}
	shstrSh := shdrs[shstrndx]
	shstrtab, err := r.view(int(shstrSh.offset), int(shstrSh.size))
	if err != nil {
		return nil, fmt.Errorf("object %q: reading shstrtab: %w", name, err)
	}

	// ── Build ObjectSection slice ─────────────────────────────────────────────

	sections := make([]*linker.ObjectSection, len(shdrs))
	for i, sh := range shdrs {
		secName, err := cstr(shstrtab, sh.nameOff)
		if err != nil {
			return nil, fmt.Errorf("object %q: section %d name: %w", name, i, err)
		}
		sec := &linker.ObjectSection{
			Name:     secName,
			Flags:    elfSectionFlags(sh.stype, sh.flags),
			Size:     sh.size,
			Align:    sh.align,
			RawType:  sh.stype,
			RawFlags: sh.flags,
			Index:    i,
			Skip:     isLinkerInternalSection(sh.stype),
		}
		if sh.stype != shtNobits && sh.size > 0 {
			sec.Data, err = r.slice(int(sh.offset), int(sh.size))
			if err != nil {
				return nil, fmt.Errorf("object %q: section %q data: %w", name, secName, err)
			}
		}
		sections[i] = sec
	}

	// ── Parse .symtab ─────────────────────────────────────────────────────────

	var symbols []*linker.ObjectSymbol

	for _, sec := range sections {
		if sec == nil || sec.RawType != shtSymtab {
			continue
		}
		sh := shdrs[sec.Index]
		if int(sh.link) >= len(sections) || sections[sh.link] == nil {
			return nil, fmt.Errorf("object %q: .symtab sh_link=%d invalid", name, sh.link)
		}
		strtabSec := sections[sh.link]
		strtab := strtabSec.Data
		if strtab == nil {
			// Read from file bytes directly if the strtab section wasn't given Data.
			strtabSh := shdrs[sh.link]
			strtab, err = r.slice(int(strtabSh.offset), int(strtabSh.size))
			if err != nil {
				return nil, fmt.Errorf("object %q: reading strtab: %w", name, err)
			}
		}

		n := int(sh.size) / symEntSize
		symbols = make([]*linker.ObjectSymbol, n)
		sr := newReader(sec.Data)

		for i := range symbols {
			base := i * symEntSize
			nameOff, _ := sr.u32(base + symoff_name)
			info := sec.Data[base+symoff_info]
			other := sec.Data[base+symoff_other]
			shndx, _ := sr.u16(base + symoff_shndx)
			value, _ := sr.u64(base + symoff_value)
			size, _ := sr.u64(base + symoff_size)

			symName, _ := cstr(strtab, nameOff)

			secIdx := linker.SymSecUndef
			secName := ""
			switch {
			case shndx == shnUndef:
				secIdx = linker.SymSecUndef
				secName = ""
			case shndx == shnAbs:
				secIdx = linker.SymSecAbs
				secName = "*ABS*"
			case shndx == shnCommon:
				secIdx = linker.SymSecCommon
				secName = "*COMMON*"
			case shndx == shnXindex:
				secIdx = linker.SymSecUndef // extended idx not common in .o files
			case shndx >= shnLoreserve:
				secIdx = linker.SymSecUndef
			default:
				secIdx = int(shndx)
				if int(shndx) < len(sections) && sections[shndx] != nil {
					secName = sections[shndx].Name
				}
			}

			symbols[i] = &linker.ObjectSymbol{
				Name:        symName,
				Value:       value,
				Size:        size,
				Binding:     elfBinding(stBind(info)),
				Type:        elfSymType(stType(info)),
				Vis:         other & 0x3,
				SectionIdx:  secIdx,
				SectionName: secName,
			}
		}
		break // at most one SHT_SYMTAB
	}

	// ── Parse RELA sections ───────────────────────────────────────────────────

	var relocs []*linker.ObjectReloc

	for _, sec := range sections {
		if sec == nil || sec.RawType != shtRela {
			continue
		}
		sh := shdrs[sec.Index]
		n := int(sh.size) / relaEntrySize
		sr := newReader(sec.Data)
		for i := 0; i < n; i++ {
			base := i * relaEntrySize
			offset, _ := sr.u64(base + relaoff_offset)
			info, _ := sr.u64(base + relaoff_info)
			addend, _ := sr.i64(base + relaoff_addend)
			relocs = append(relocs, &linker.ObjectReloc{
				TargetSectionIdx: int(sh.info),
				Offset:           offset,
				SymIdx:           relaSymIdx(info),
				Type:             relaType(info),
				Addend:           addend,
			})
		}
	}

	return &linker.Object{
		Name:     name,
		Machine:  machine,
		EFlags:   eflags,
		Sections: sections,
		Symbols:  symbols,
		Relocs:   relocs,
	}, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func elfSectionFlags(shType uint32, shFlags uint64) linker.SectionFlags {
	var f linker.SectionFlags
	if shFlags&SHF_ALLOC != 0 {
		f |= linker.SecAlloc
	}
	if shFlags&SHF_WRITE != 0 {
		f |= linker.SecWrite
	}
	if shFlags&SHF_EXECINSTR != 0 {
		f |= linker.SecExec
	}
	if shFlags&SHF_TLS != 0 {
		f |= linker.SecTLS
	}
	if shType == shtNobits {
		f |= linker.SecBSS
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

func elfBinding(b uint8) linker.SymBinding {
	switch b {
	case STB_GLOBAL:
		return linker.BindGlobal
	case STB_WEAK:
		return linker.BindWeak
	default:
		return linker.BindLocal
	}
}

func elfSymType(t uint8) linker.SymType {
	switch t {
	case STT_OBJECT:
		return linker.SymTypeObject
	case STT_FUNC:
		return linker.SymTypeFunc
	case STT_SECTION:
		return linker.SymTypeSection
	case STT_FILE:
		return linker.SymTypeFile
	case STT_TLS:
		return linker.SymTypeTLS
	default:
		return linker.SymTypeNone
	}
}