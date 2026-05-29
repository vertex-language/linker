// Package macho implements a self-contained Mach-O linker for AMD64 and ARM64
// targets on macOS / Darwin, producing MH_EXECUTE, OutputPIE, and MH_DYLIB output.
//
// Usage:
//
//	l := macho.NewLinker(macho.ArchAMD64)
//	l.SetOutputType(macho.OutputExec)
//	l.SetEntryPoint("_main")
//	l.AddObject("main.o", data)
//	l.AddDynamicLibrary("libSystem.B.dylib", libSystemBytes)
//	exe, err := l.Link()
package macho

// Arch identifies the target CPU architecture for Mach-O output.
type Arch uint8

const (
	ArchAMD64 Arch = iota + 1 // x86-64 macOS
	ArchARM64                  // AArch64 / Apple Silicon macOS
)

// pltState is shared between the PLT patcher and the relocation patcher so
// that the stub→GOT mapping written during patchPLT is visible to Apply.
type pltState struct {
	stubToGOT map[uint64]uint64
	gotBase   uint64
	pltBase   uint64
}

// machoBackend owns all format-specific operations.  Its methods are all
// unexported; the Linker is the only caller.
type machoBackend struct {
	arch  Arch
	state *pltState
}

func (b *machoBackend) baseVA(ot OutputType) uint64 {
	if ot == OutputShared {
		return 0
	}
	return 0x100000000 // canonical __TEXT base for macOS executables
}

func (b *machoBackend) injectPLT(layout *Layout, syms []PLTEntry) error {
	return injectMachoPLT(b.arch, layout, syms)
}

func (b *machoBackend) parseObject(name string, data []byte) (*Object, error) {
	return parseObject(name, data, b.arch)
}

func (b *machoBackend) parseSharedLib(name string, data []byte) (*SharedLib, error) {
	return parseSharedLib(name, data)
}

func (b *machoBackend) patcher() Patcher {
	return newMachoPatcher(b.arch, b.state)
}

func (b *machoBackend) pltPatcher() PLTPatcher {
	return newMachoPLTPatcher(b.arch, b.state)
}

func (b *machoBackend) emit(req *emitRequest) ([]byte, error) {
	return emitMachO(req, b.arch)
}