package pe

import (
	"encoding/binary"
	"sort"
)

// IATLayout records how PLT symbols are grouped into contiguous IAT slots
// inside .got.plt (after the 3 reserved header entries).
type IATLayout struct {
	DLLOrder []string
	SlotOf   []int
	DLLStart map[string]int
	DLLCount map[string]int
}

func computeIATLayout(syms []PLTEntry) *IATLayout {
	var dllOrder []string
	dllSeen  := make(map[string]bool)
	dllCount := make(map[string]int)

	for _, s := range syms {
		dll := dllName(s)
		if !dllSeen[dll] {
			dllSeen[dll] = true
			dllOrder = append(dllOrder, dll)
		}
		dllCount[dll]++
	}

	dllStart := make(map[string]int)
	slot := 0
	for _, dll := range dllOrder {
		dllStart[dll] = slot
		slot += dllCount[dll] + 1
	}

	slotOf   := make([]int, len(syms))
	localIdx := make(map[string]int)
	for i, s := range syms {
		dll        := dllName(s)
		slotOf[i]   = dllStart[dll] + localIdx[dll]
		localIdx[dll]++
	}

	return &IATLayout{
		DLLOrder: dllOrder,
		SlotOf:   slotOf,
		DLLStart: dllStart,
		DLLCount: dllCount,
	}
}

func (l *IATLayout) totalGOTSlots() int {
	total := 3
	for _, dll := range l.DLLOrder {
		total += l.DLLCount[dll] + 1
	}
	return total
}

func dllName(s PLTEntry) string {
	if s.Sym != nil && s.Sym.Lib != nil {
		return s.Sym.Lib.Soname
	}
	return ""
}

func buildIdata(
	req      *EmitRequest,
	layout   *IATLayout,
	coreBase uint64,
) (body []byte, importDirRVA, importDirSize, iatRVA, iatSize uint32) {

	symtab := req.Symtab
	gotSec, hasGot := req.Layout.SectionByName(".got.plt")
	if !hasGot || layout == nil || len(layout.DLLOrder) == 0 {
		return nil, 0, 0, 0, 0
	}

	iatBaseRVA := toRVA(gotSec.VAddr, coreBase) + 3*8

	nDLLs := len(layout.DLLOrder)

	type impSym struct {
		name string
		hint uint16
		dll  string
		idx  int
	}
	var allImpSyms []impSym
	for i, sname := range req.PLTSyms {
		ts := symtab.Lookup(sname)
		if ts == nil || ts.Lib == nil {
			continue
		}
		allImpSyms = append(allImpSyms, impSym{
			name: sname,
			dll:  ts.Lib.Soname,
			idx:  i,
		})
	}

	dllImpSyms := make(map[string][]impSym)
	for _, is := range allImpSyms {
		dllImpSyms[is.dll] = append(dllImpSyms[is.dll], is)
	}
	for dll := range dllImpSyms {
		sort.Slice(dllImpSyms[dll], func(a, b int) bool {
			return dllImpSyms[dll][a].idx < dllImpSyms[dll][b].idx
		})
	}

	importTableSize := (nDLLs + 1) * sizeImportDesc

	iltSize := 0
	for _, dll := range layout.DLLOrder {
		iltSize += (layout.DLLCount[dll] + 1) * 8
	}

	type hnEntry struct {
		hint   uint16
		name   string
		offset int
	}
	dllHNEntries := make(map[string][]hnEntry)
	hnTotal := 0
	for _, dll := range layout.DLLOrder {
		for _, is := range dllImpSyms[dll] {
			ent := hnEntry{hint: is.hint, name: is.name, offset: hnTotal}
			sz := 2 + len(is.name) + 1
			if sz%2 != 0 {
				sz++
			}
			hnTotal += sz
			dllHNEntries[dll] = append(dllHNEntries[dll], ent)
		}
	}

	dllNameOffsets := make(map[string]int)
	dllNameArea    := make([]byte, 0)
	for _, dll := range layout.DLLOrder {
		dllNameOffsets[dll] = len(dllNameArea)
		dllNameArea = append(dllNameArea, []byte(dll)...)
		dllNameArea = append(dllNameArea, 0)
		if len(dllNameArea)%2 != 0 {
			dllNameArea = append(dllNameArea, 0)
		}
	}

	iltOff    := importTableSize
	hnOff     := iltOff + iltSize
	dllNOff   := hnOff + hnTotal
	totalSize := dllNOff + len(dllNameArea)

	body = make([]byte, totalSize)

	descPtr   := 0
	iltCursor := iltOff
	for _, dll := range layout.DLLOrder {
		dllSymList := dllImpSyms[dll]

		binary.LittleEndian.PutUint32(body[descPtr:], uint32(iltCursor))
		binary.LittleEndian.PutUint32(body[descPtr+4:], 0)
		binary.LittleEndian.PutUint32(body[descPtr+8:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(body[descPtr+12:], uint32(dllNOff+dllNameOffsets[dll]))
		firstThunkRVA := iatBaseRVA + uint32(layout.DLLStart[dll])*8
		binary.LittleEndian.PutUint32(body[descPtr+16:], firstThunkRVA)
		descPtr += sizeImportDesc

		for j := range dllSymList {
			hnIdx := dllHNEntries[dll][j].offset
			binary.LittleEndian.PutUint64(body[iltCursor:], uint64(hnOff+hnIdx))
			iltCursor += 8
		}
		binary.LittleEndian.PutUint64(body[iltCursor:], 0)
		iltCursor += 8
	}

	hnCursor := hnOff
	for _, dll := range layout.DLLOrder {
		for _, ent := range dllHNEntries[dll] {
			binary.LittleEndian.PutUint16(body[hnCursor:], ent.hint)
			copy(body[hnCursor+2:], ent.name)
			body[hnCursor+2+len(ent.name)] = 0
			sz := 2 + len(ent.name) + 1
			if sz%2 != 0 {
				sz++
			}
			hnCursor += sz
		}
	}

	copy(body[dllNOff:], dllNameArea)

	importDirSize = uint32(importTableSize)
	iatSize       = uint32((len(allImpSyms) + len(layout.DLLOrder)) * 8)
	_ = nDLLs
	return body, 0, importDirSize, iatBaseRVA, iatSize
}

func patchIdataRVAs(body []byte, layout *IATLayout, selfRVA uint32,
	req *EmitRequest, iatBaseRVA uint32) {

	symtab := req.Symtab

	type impSym struct {
		name string
		dll  string
		idx  int
	}
	var allImpSyms []impSym
	for i, sname := range req.PLTSyms {
		ts := symtab.Lookup(sname)
		if ts == nil || ts.Lib == nil {
			continue
		}
		allImpSyms = append(allImpSyms, impSym{name: sname, dll: ts.Lib.Soname, idx: i})
	}
	dllImpSyms := make(map[string][]impSym)
	for _, is := range allImpSyms {
		dllImpSyms[is.dll] = append(dllImpSyms[is.dll], is)
	}
	for dll := range dllImpSyms {
		sort.Slice(dllImpSyms[dll], func(a, b int) bool {
			return dllImpSyms[dll][a].idx < dllImpSyms[dll][b].idx
		})
	}

	nDLLs           := len(layout.DLLOrder)
	importTableSize := (nDLLs + 1) * sizeImportDesc

	iltSize := 0
	for _, dll := range layout.DLLOrder {
		iltSize += (layout.DLLCount[dll] + 1) * 8
	}

	type hnEntry struct {
		hint   uint16
		name   string
		offset int
	}
	dllHNEntries := make(map[string][]hnEntry)
	hnTotal := 0
	for _, dll := range layout.DLLOrder {
		for _, is := range dllImpSyms[dll] {
			ent := hnEntry{offset: hnTotal, name: is.name}
			sz := 2 + len(is.name) + 1
			if sz%2 != 0 {
				sz++
			}
			hnTotal += sz
			dllHNEntries[dll] = append(dllHNEntries[dll], ent)
		}
	}

	dllNameOffsets := make(map[string]int)
	cur := 0
	for _, dll := range layout.DLLOrder {
		dllNameOffsets[dll] = cur
		cur += len(dll) + 1
		if cur%2 != 0 {
			cur++
		}
	}

	iltOff  := importTableSize
	hnOff   := iltOff + iltSize
	dllNOff := hnOff + hnTotal

	descPtr   := 0
	iltCursor := iltOff
	for _, dll := range layout.DLLOrder {
		binary.LittleEndian.PutUint32(body[descPtr:], selfRVA+uint32(iltCursor))
		binary.LittleEndian.PutUint32(body[descPtr+12:], selfRVA+uint32(dllNOff+dllNameOffsets[dll]))
		descPtr   += sizeImportDesc
		iltCursor += (layout.DLLCount[dll] + 1) * 8
	}

	iltCursor = iltOff
	for _, dll := range layout.DLLOrder {
		for j := range dllHNEntries[dll] {
			hnOff64 := uint64(selfRVA + uint32(hnOff+dllHNEntries[dll][j].offset))
			binary.LittleEndian.PutUint64(body[iltCursor:], hnOff64)
			iltCursor += 8
		}
		iltCursor += 8
	}
}

func buildBaseRelocSection(sites []BaseRelocSite, coreBase uint64) []byte {
	if len(sites) == 0 {
		return nil
	}

	sort.Slice(sites, func(i, j int) bool { return sites[i].VA < sites[j].VA })

	var out []byte
	i := 0
	for i < len(sites) {
		pageBase := sites[i].VA &^ 0xFFF

		var entries []uint16
		for i < len(sites) && (sites[i].VA&^0xFFF) == pageBase {
			offset := uint16(sites[i].VA & 0xFFF)
			entries = append(entries, (baseRelocDir64<<12)|offset)
			i++
		}
		if len(entries)%2 != 0 {
			entries = append(entries, 0)
		}
		blockSize := uint32(sizeBaseRelocBlock + len(entries)*2)

		var hdr [8]byte
		binary.LittleEndian.PutUint32(hdr[0:], uint32(pageBase-coreBase))
		binary.LittleEndian.PutUint32(hdr[4:], blockSize)
		out = append(out, hdr[:]...)
		for _, e := range entries {
			var buf [2]byte
			binary.LittleEndian.PutUint16(buf[:], e)
			out = append(out, buf[:]...)
		}
	}
	return out
}