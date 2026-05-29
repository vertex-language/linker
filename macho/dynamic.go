package macho

import (
	"encoding/binary"
	"fmt"
)

// ── Core PLT types ────────────────────────────────────────────────────────────

// PLTEntry pairs a shared symbol with its 0-based stub index.
type PLTEntry struct {
	Name string
	Sym  *TableSymbol
	Idx  int
}

// PLTPatcher writes arch-specific PLT stubs.
type PLTPatcher interface {
	PatchPLT(plt, gotPLT, relaPLT []byte, pltBase, gotBase uint64, syms []PLTEntry)
}

// collectPLTSymbols returns every kindShared symbol referenced by at least one
// object relocation, in stable first-seen order.
func collectPLTSymbols(symtab *SymbolTable, objects []*Object) []PLTEntry {
	referenced := make(map[string]bool)
	for _, obj := range objects {
		for _, rel := range obj.Relocs {
			if int(rel.SymIdx) < len(obj.Symbols) && obj.Symbols[rel.SymIdx] != nil {
				if name := obj.Symbols[rel.SymIdx].Name; name != "" {
					referenced[name] = true
				}
			}
		}
	}

	var out []PLTEntry
	seen := make(map[string]bool)
	for _, obj := range objects {
		for _, raw := range obj.Symbols {
			if raw == nil || raw.Name == "" || seen[raw.Name] || !referenced[raw.Name] {
				continue
			}
			sym := symtab.Lookup(raw.Name)
			if sym == nil || !sym.IsShared() {
				continue
			}
			seen[raw.Name] = true
			out = append(out, PLTEntry{Name: raw.Name, Sym: sym, Idx: len(out)})
		}
	}
	return out
}

// patchPLT fills PLT stubs and GOT slots via the patcher.
func patchPLT(pp PLTPatcher, layout *Layout, syms []PLTEntry) error {
	pltSec, ok1 := layout.SectionByName(sectionStubs)
	gotSec, ok2 := layout.SectionByName(sectionGOT)
	if !ok1 || !ok2 {
		return nil
	}
	// Mach-O uses dyld info instead of a rela section; pass nil for the third slice.
	pp.PatchPLT(pltSec.Data, gotSec.Data, nil, pltSec.VAddr, gotSec.VAddr, syms)
	return nil
}

// ── Mach-O stub / GOT constants ───────────────────────────────────────────────

const (
	stubSizeAMD64 = 6  // jmpq *[rip+offset]
	stubSizeARM64 = 12 // ADRP + LDR + BR
	gotEntrySize  = 8  // 64-bit pointer slot
)

const (
	sectionStubs = "__TEXT/__stubs"
	sectionGOT   = "__DATA/__got"
)

// injectMachoPLT adds __TEXT/__stubs and __DATA/__got to the layout.
func injectMachoPLT(arch Arch, layout *Layout, syms []PLTEntry) error {
	n := len(syms)
	if n == 0 {
		return nil
	}

	stubSz := stubSizeAMD64
	if arch == ArchARM64 {
		stubSz = stubSizeARM64
	}

	stubs := &MergedSection{
		Name:     sectionStubs,
		Flags:    SecAlloc | SecExec,
		RawType:  uint32(S_SYMBOL_STUBS),
		RawFlags: uint64(S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS),
		Data:     make([]byte, n*stubSz),
		Size:     uint64(n * stubSz),
		Align:    4,
	}
	got := &MergedSection{
		Name:     sectionGOT,
		Flags:    SecAlloc | SecWrite,
		RawType:  uint32(S_NON_LAZY_SYMBOL_POINTERS),
		RawFlags: uint64(S_NON_LAZY_SYMBOL_POINTERS),
		Data:     make([]byte, n*gotEntrySize),
		Size:     uint64(n * gotEntrySize),
		Align:    8,
	}

	// Both Sections slice and the name index must be updated together.
	layout.Sections = append(layout.Sections, stubs, got)
	layout.secByName[stubs.Name] = stubs
	layout.secByName[got.Name] = got
	return nil
}

// ── PLT patcher ───────────────────────────────────────────────────────────────

type machoPLTPatcher struct {
	arch  Arch
	state *pltState
}

func newMachoPLTPatcher(arch Arch, state *pltState) *machoPLTPatcher {
	return &machoPLTPatcher{arch: arch, state: state}
}

func (p *machoPLTPatcher) PatchPLT(
	pltData, gotData, _ []byte,
	pltBase, gotBase uint64,
	syms []PLTEntry,
) {
	p.state.pltBase = pltBase
	p.state.gotBase = gotBase

	for _, sym := range syms {
		i := sym.Idx
		stubVA := pltBase + uint64(i)*stubEntrySize(p.arch)
		gotVA := gotBase + uint64(i)*gotEntrySize

		p.state.stubToGOT[stubVA] = gotVA
		sym.Sym.VAddr = stubVA

		stubOff := i * int(stubEntrySize(p.arch))
		switch p.arch {
		case ArchAMD64:
			writeAMD64Stub(pltData[stubOff:], stubVA, gotVA)
		case ArchARM64:
			writeARM64Stub(pltData[stubOff:], stubVA, gotVA)
		}
	}
}

func stubEntrySize(arch Arch) uint64 {
	if arch == ArchARM64 {
		return stubSizeARM64
	}
	return stubSizeAMD64
}

func writeAMD64Stub(buf []byte, stubVA, gotVA uint64) {
	buf[0] = 0xFF
	buf[1] = 0x25
	rel := int32(int64(gotVA) - int64(stubVA+6))
	binary.LittleEndian.PutUint32(buf[2:], uint32(rel))
}

func writeARM64Stub(buf []byte, stubVA, gotVA uint64) {
	const x16 = 16
	binary.LittleEndian.PutUint32(buf[0:], encodeADRP(x16, stubVA, gotVA))
	binary.LittleEndian.PutUint32(buf[4:], encodeLDR64UnsignedOffset(x16, x16, uint32(gotVA&0xFFF)))
	binary.LittleEndian.PutUint32(buf[8:], 0xD61F0200) // BR X16
}

// ── Reloc patcher ─────────────────────────────────────────────────────────────

type machoPatcher struct {
	arch  Arch
	state *pltState
}

func newMachoPatcher(arch Arch, state *pltState) *machoPatcher {
	return &machoPatcher{arch: arch, state: state}
}

func (p *machoPatcher) Apply(data []byte, off int, relType uint32, P, S uint64, A int64) error {
	switch p.arch {
	case ArchAMD64:
		return applyAMD64(data, off, relType, P, S, A, p.state)
	case ArchARM64:
		return applyARM64(data, off, relType, P, S, A, p.state)
	}
	return fmt.Errorf("macho: unknown arch %d", p.arch)
}

// ── dyld LINKEDIT builders ────────────────────────────────────────────────────

// BuildRebaseInfo produces a minimal REBASE opcode stream.
func BuildRebaseInfo() []byte {
	return []byte{REBASE_OPCODE_DONE}
}

// BuildExportTrie produces a minimal empty export trie (for executables).
func BuildExportTrie() []byte {
	return []byte{0x00, 0x00} // root: terminal_size=0, child_count=0
}

// trieEntry is used internally for trie construction.
type trieEntry struct {
	name string
	addr uint64
}

// BuildExportTrieForSymbols produces an export trie for MH_DYLIB output.
func BuildExportTrieForSymbols(exports map[string]uint64) []byte {
	if len(exports) == 0 {
		return BuildExportTrie()
	}
	entries := make([]trieEntry, 0, len(exports))
	for k, v := range exports {
		entries = append(entries, trieEntry{k, v})
	}
	return buildLinearTrie(entries)
}

// BuildBindInfo produces the BIND opcode stream that instructs dyld to fill
// each GOT slot with the address of the corresponding imported symbol.
func BuildBindInfo(
	pltSyms []string,
	gotSec *MergedSection,
	dataSegIndex uint32,
	neededLibs []string,
	req *emitRequest,
) []byte {
	if len(pltSyms) == 0 || gotSec == nil {
		return []byte{BIND_OPCODE_DONE}
	}

	ordinalOf := make(map[string]int, len(neededLibs))
	for i, s := range neededLibs {
		ordinalOf[s] = i + 1
	}

	dataBase := dataSegVMAddr(req)

	var buf []byte
	prevSegOff := uint64(0)
	firstEntry := true

	for i, symName := range pltSyms {
		gotOffset := uint64(i) * gotEntrySize
		segOff := gotSec.VAddr - dataBase + gotOffset

		ordinal := 1
		if sym := req.Symtab.Lookup(symName); sym != nil && sym.Lib != nil {
			if ord, ok := ordinalOf[sym.Lib.Soname]; ok {
				ordinal = ord
			}
		}

		// Always emit the dylib ordinal (simplified; a production encoder would
		// suppress repeated identical ordinals).
		if ordinal > 0 && ordinal <= 15 {
			buf = append(buf, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM|uint8(ordinal))
		} else {
			buf = append(buf, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB)
			buf = appendULEB128(buf, uint64(ordinal))
		}

		buf = append(buf, BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM|0x00)
		buf = append(buf, []byte(symName)...)
		buf = append(buf, 0x00)

		buf = append(buf, BIND_OPCODE_SET_TYPE_IMM|BIND_TYPE_POINTER)

		if firstEntry {
			buf = append(buf, BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB|uint8(dataSegIndex))
			buf = appendULEB128(buf, segOff)
		} else {
			buf = append(buf, BIND_OPCODE_ADD_ADDR_ULEB)
			buf = appendULEB128(buf, segOff-prevSegOff)
		}
		prevSegOff = segOff
		firstEntry = false

		buf = append(buf, BIND_OPCODE_DO_BIND)
	}

	buf = append(buf, BIND_OPCODE_DONE)
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func dataSegVMAddr(req *emitRequest) uint64 {
	for _, sec := range req.Layout.Sections {
		if sec.Flags&SecAlloc != 0 && sec.Flags&SecWrite != 0 {
			return sec.VAddr
		}
	}
	return 0
}

// ── Export trie ───────────────────────────────────────────────────────────────

type trieEdge struct {
	label string
	child *trieNode
}

type trieNode struct {
	edges     []trieEdge
	hasExport bool
	addr      uint64
}

func buildLinearTrie(entries []trieEntry) []byte {
	root := &trieNode{}
	for _, e := range entries {
		insertTrie(root, e.name, e.addr)
	}
	var buf []byte
	serializeTrie(root, &buf)
	return buf
}

func insertTrie(node *trieNode, name string, addr uint64) {
	if name == "" {
		node.hasExport = true
		node.addr = addr
		return
	}
	for i := range node.edges {
		e := &node.edges[i]
		common := commonPrefix(e.label, name)
		if common == 0 {
			continue
		}
		if common == len(e.label) {
			insertTrie(e.child, name[common:], addr)
			return
		}
		newChild := &trieNode{edges: []trieEdge{{label: e.label[common:], child: e.child}}}
		e.label = e.label[:common]
		e.child = newChild
		insertTrie(newChild, name[common:], addr)
		return
	}
	child := &trieNode{}
	node.edges = append(node.edges, trieEdge{label: name, child: child})
	insertTrie(child, "", addr)
}

func commonPrefix(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func serializeTrie(node *trieNode, buf *[]byte) {
	var terminal []byte
	if node.hasExport {
		flagBytes := appendULEB128(nil, EXPORT_SYMBOL_FLAGS_KIND_REGULAR)
		addrBytes := appendULEB128(nil, node.addr)
		terminal = appendULEB128(nil, uint64(len(flagBytes)+len(addrBytes)))
		terminal = append(terminal, flagBytes...)
		terminal = append(terminal, addrBytes...)
	} else {
		terminal = []byte{0x00}
	}
	*buf = append(*buf, terminal...)
	*buf = append(*buf, uint8(len(node.edges)))
	for _, e := range node.edges {
		*buf = append(*buf, []byte(e.label)...)
		*buf = append(*buf, 0x00)
		childOff := len(*buf) + 5
		*buf = appendULEB128(*buf, uint64(childOff))
	}
	for _, e := range node.edges {
		serializeTrie(e.child, buf)
	}
}