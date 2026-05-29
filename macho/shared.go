package macho

import (
	"fmt"
	"strings"
)

func parseSharedLib(name string, data []byte) (*SharedLib, error) {
	r := newReader(data, name)

	magic, err := r.U32(0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if magic != MH_MAGIC_64 {
		return nil, fmt.Errorf("%s: unsupported Mach-O magic 0x%X", name, magic)
	}
	fileType, err := r.U32(12)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if fileType != MH_DYLIB && fileType != MH_EXECUTE {
		return nil, fmt.Errorf("%s: not a dylib or executable (filetype 0x%X)", name, fileType)
	}

	ncmds, err := r.U32(16)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	lib := &SharedLib{
		Name:    name,
		Exports: make(map[string]*SharedExport),
	}

	var symoff, nsyms, stroff, strsize uint32
	var exportOff, exportSize uint32

	pos := machHeaderSize64
	for i := uint32(0); i < ncmds; i++ {
		cmd, err := r.U32(pos)
		if err != nil {
			break
		}
		cmdsize, err := r.U32(pos + 4)
		if err != nil || cmdsize < 8 {
			break
		}

		switch cmd {
		case LC_ID_DYLIB:
			nameOff, _ := r.U32(pos + 8)
			if nameOff >= 8 {
				soname, _ := r.CString(pos+int(nameOff), int(cmdsize)-int(nameOff))
				lib.Soname = dylibBasename(soname)
			}

		case LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB:
			nameOff, _ := r.U32(pos + 8)
			if nameOff >= 8 {
				depName, _ := r.CString(pos+int(nameOff), int(cmdsize)-int(nameOff))
				lib.Needed = append(lib.Needed, dylibBasename(depName))
			}

		case LC_RPATH:
			pathOff, _ := r.U32(pos + 8)
			if pathOff >= 8 {
				rpath, _ := r.CString(pos+int(pathOff), int(cmdsize)-int(pathOff))
				lib.Rpaths = append(lib.Rpaths, rpath)
			}

		case LC_SYMTAB:
			symoff, _ = r.U32(pos + 8)
			nsyms, _ = r.U32(pos + 12)
			stroff, _ = r.U32(pos + 16)
			strsize, _ = r.U32(pos + 20)

		case LC_DYLD_INFO_ONLY:
			exportOff, _ = r.U32(pos + 32)
			exportSize, _ = r.U32(pos + 36)
		}

		pos += int(cmdsize)
	}

	if lib.Soname == "" {
		lib.Soname = dylibBasename(name)
	}

	// Prefer the export trie.
	if exportOff > 0 && exportSize > 0 && int(exportOff+exportSize) <= len(data) {
		parseExportTrie(data[exportOff:exportOff+exportSize], lib)
	}

	// Supplement / fall back to LC_SYMTAB.
	if nsyms > 0 && symoff > 0 && stroff > 0 {
		for i := uint32(0); i < nsyms; i++ {
			soff := int(symoff) + int(i)*nlist64Size
			strx, err := r.U32(soff)
			if err != nil {
				break
			}
			ntype, _ := r.U8(soff + 4)
			ndesc, _ := r.U16(soff + 6)
			nvalue, _ := r.U64(soff + 8)

			if ntype&N_STAB != 0 {
				continue
			}
			if ntype&N_TYPE != N_SECT || ntype&N_EXT == 0 {
				continue
			}

			symName := ""
			if strx < strsize {
				symName, _ = r.CString(int(stroff)+int(strx), int(strsize-strx))
			}
			if symName == "" {
				continue
			}

			binding := BindGlobal
			if ndesc&N_WEAK_DEF != 0 {
				binding = BindWeak
			}

			if _, exists := lib.Exports[symName]; !exists {
				lib.Exports[symName] = &SharedExport{
					Name:    symName,
					Value:   nvalue,
					Binding: binding,
					Type:    SymTypeFunc,
				}
			}
		}
	}

	return lib, nil
}

func parseExportTrie(trieData []byte, lib *SharedLib) {
	var walk func(off int, prefix string)
	walk = func(off int, prefix string) {
		if off >= len(trieData) {
			return
		}
		termSize, n, err := readULEB128(trieData, off)
		if err != nil {
			return
		}
		off += n

		if termSize > 0 {
			flags, fn, err := readULEB128(trieData, off)
			if err != nil {
				return
			}
			off += fn
			if flags&EXPORT_SYMBOL_FLAGS_REEXPORT == 0 {
				addr, an, err := readULEB128(trieData, off)
				if err == nil {
					off += an
					if _, exists := lib.Exports[prefix]; !exists {
						binding := BindGlobal
						if flags&EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0 {
							binding = BindWeak
						}
						lib.Exports[prefix] = &SharedExport{
							Name:    prefix,
							Value:   addr,
							Binding: binding,
							Type:    SymTypeFunc,
						}
					}
				}
			}
			off = int(uint64(off-fn-n)+termSize) + n
		}

		if off >= len(trieData) {
			return
		}
		childCount := int(trieData[off])
		off++

		for c := 0; c < childCount; c++ {
			if off >= len(trieData) {
				return
			}
			labelEnd := off
			for labelEnd < len(trieData) && trieData[labelEnd] != 0 {
				labelEnd++
			}
			label := string(trieData[off:labelEnd])
			off = labelEnd + 1

			childOff, cn, err := readULEB128(trieData, off)
			if err != nil {
				return
			}
			off += cn
			walk(int(childOff), prefix+label)
		}
	}
	walk(0, "")
}

func dylibBasename(path string) string {
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[idx+1:]
	}
	return path
}