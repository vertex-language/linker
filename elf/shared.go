// shared.go — ELF64 ET_DYN shared library parser producing *linker.SharedLib.
package elf

import (
	"fmt"

	"github.com/vertex-language/linker"
)

// ParseSharedLib parses an ELF64 ET_DYN shared object from raw bytes.
func ParseSharedLib(name string, data []byte) (*linker.SharedLib, error) {
	r := newReader(data)

	if len(data) < ehdrSize {
		return nil, fmt.Errorf("shared %q: file too small", name)
	}
	if string(data[0:4]) != "\x7fELF" {
		return nil, fmt.Errorf("shared %q: bad ELF magic", name)
	}
	if data[EI_CLASS] != elfClass64 {
		return nil, fmt.Errorf("shared %q: not ELF64", name)
	}
	if data[EI_DATA] != elfData2LSB {
		return nil, fmt.Errorf("shared %q: only little-endian supported", name)
	}

	eType, _ := r.u16(ehoff_type)
	if eType != etDyn && eType != etExec {
		return nil, fmt.Errorf("shared %q: not ET_DYN or ET_EXEC (e_type=%d)", name, eType)
	}

	shoff, _ := r.u64(ehoff_shoff)
	shentsize, _ := r.u16(ehoff_shentsize)
	shnum, _ := r.u16(ehoff_shnum)
	shstrndx, _ := r.u16(ehoff_shstrndx)

	if shentsize < shdrSize || shnum == 0 {
		return nil, fmt.Errorf("shared %q: no section headers", name)
	}

	// ── Read section headers ───────────────────────────────────────────────────

	type secInfo struct {
		name    string
		stype   uint32
		addr    uint64
		offset  uint64
		size    uint64
		link    uint32
		entsize uint64
	}

	secs := make([]secInfo, shnum)
	for i := range secs {
		base := int(shoff) + i*int(shentsize)
		secs[i].stype, _ = r.u32(base + shoff_type)
		secs[i].addr, _  = r.u64(base + shoff_addr)
		secs[i].offset, _ = r.u64(base + shoff_offset)
		secs[i].size, _   = r.u64(base + shoff_size)
		secs[i].link, _   = r.u32(base + shoff_link)
		secs[i].entsize, _ = r.u64(base + shoff_entsize)
	}

	// Read section names from .shstrtab.
	if int(shstrndx) < len(secs) {
		sh := secs[shstrndx]
		if shstrtab, err := r.view(int(sh.offset), int(sh.size)); err == nil {
			for i := range secs {
				base := int(shoff) + i*int(shentsize)
				nameOff, _ := r.u32(base + shoff_name)
				secs[i].name, _ = cstr(shstrtab, nameOff)
			}
		}
	}

	// Helper: resolve virtual address to file offset.
	vaToFile := func(vaddr uint64) (uint64, bool) {
		for _, s := range secs {
			if s.addr != 0 && vaddr >= s.addr && vaddr < s.addr+s.size {
				return s.offset + (vaddr - s.addr), true
			}
		}
		return 0, false
	}

	// ── Walk .dynamic section ─────────────────────────────────────────────────

	lib := &linker.SharedLib{
		Name:    name,
		Exports: make(map[string]*linker.SharedExport),
	}

	var (
		dynStrtabVA uint64
		dynStrtabSz uint64
		dynSymtabVA uint64
		sonameOff   uint64
	)
	// Placeholder strings resolved after we find the dynamic string table.
	type deferred struct{ ptr *string; off uint64 }
	var deferredNeeded []uint64
	var deferredRpath  []uint64

	for _, sec := range secs {
		if sec.stype != shtDynamic {
			continue
		}
		n := int(sec.size) / dynEntSize
		dr := newReader(data)
	dynLoop:
		for i := 0; i < n; i++ {
			base := int(sec.offset) + i*dynEntSize
			tag, _ := dr.i64(base + dynoff_tag)
			val, _ := dr.u64(base + dynoff_val)
			switch tag {
			case DT_NULL:
				break dynLoop
			case DT_NEEDED:
				deferredNeeded = append(deferredNeeded, val)
			case DT_STRTAB:
				dynStrtabVA = val
			case DT_STRSZ:
				dynStrtabSz = val
			case DT_SYMTAB:
				dynSymtabVA = val
			case DT_SONAME:
				sonameOff = val
			case DT_RPATH, DT_RUNPATH:
				deferredRpath = append(deferredRpath, val)
			}
		}
		break
	}
	_ = dynSymtabVA

	// ── Resolve dynamic string table ──────────────────────────────────────────

	var dynstrtab []byte
	if dynStrtabVA != 0 {
		if foff, ok := vaToFile(dynStrtabVA); ok {
			sz := dynStrtabSz
			if sz == 0 {
				sz = 4096
			}
			dynstrtab, _ = r.view(int(foff), int(sz))
		}
	}
	if dynstrtab == nil {
		for _, sec := range secs {
			if sec.name == ".dynstr" && sec.stype == shtStrtab {
				dynstrtab, _ = r.view(int(sec.offset), int(sec.size))
				break
			}
		}
	}

	resolve := func(off uint64) string {
		if dynstrtab == nil {
			return fmt.Sprintf("@strtab:%d", off)
		}
		s, _ := cstr(dynstrtab, uint32(off))
		return s
	}

	for _, off := range deferredNeeded {
		lib.Needed = append(lib.Needed, resolve(off))
	}
	for _, off := range deferredRpath {
		lib.Rpaths = append(lib.Rpaths, resolve(off))
	}
	if sonameOff != 0 {
		lib.Soname = resolve(sonameOff)
	}
	if lib.Soname == "" {
		lib.Soname = name
	}

	// ── Parse .dynsym ─────────────────────────────────────────────────────────

	var dynsymOff, dynsymSize uint64
	for _, sec := range secs {
		if sec.stype == shtDynsym {
			dynsymOff = sec.offset
			dynsymSize = sec.size
			break
		}
	}

	if dynsymOff != 0 && dynsymSize > 0 && dynstrtab != nil {
		n := int(dynsymSize) / symEntSize
		sr := newReader(data)
		for i := 0; i < n; i++ {
			base := int(dynsymOff) + i*symEntSize
			nameOff, _ := sr.u32(base + symoff_name)
			info := data[base+symoff_info]
			shndx, _ := sr.u16(base + symoff_shndx)
			value, _ := sr.u64(base + symoff_value)
			size, _ := sr.u64(base + symoff_size)

			symName, _ := cstr(dynstrtab, nameOff)
			if symName == "" || shndx == shnUndef {
				continue
			}

			lib.Exports[symName] = &linker.SharedExport{
				Name:    symName,
				Value:   value,
				Size:    size,
				Binding: elfBinding(stBind(info)),
				Type:    elfSymType(stType(info)),
			}
		}
	}

	return lib, nil
}