# linker/elf

ELF64 linker sub-package for `github.com/vertex-language/linker`.  
Supports AMD64, ARM64, and RISC-V 64 targets.

## Import

```go
import "github.com/vertex-language/linker/elf"
```

---

## Quick start

```go
l := elf.NewLinker(elf.ArchAMD64)
l.SetEntryPoint("_start")

l.AddObject("main.o", mainBytes)
l.AddArchive("libc.a", libcBytes)
l.AddDynamicLibrary("libc.so.6", libcSOBytes)

out, err := l.Link()
if err != nil {
    log.Fatal(err)
}
os.WriteFile("a.out", out, 0755)
```

---

## Linker

```go
l := elf.NewLinker(arch)          // sets default interpreter for the arch
l.SetOutputType(elf.OutputExec)   // OutputExec | OutputPIE | OutputShared
l.SetEntryPoint("_start")
l.SetInterp("/lib64/ld-linux-x86-64.so.2") // override default interp
l.SetSoname("libfoo.so.1")        // shared library only
l.SetRpath("/usr/local/lib")
l.AddLibraryPath("/opt/lib")      // searched when walking transitive deps

l.AddObject("foo.o", data)        // ET_REL relocatable object
l.AddArchive("libbar.a", data)    // static archive; members extracted on demand
l.AddDynamicLibrary("libc.so.6", data) // ET_DYN shared library
l.AddSONeeded("libm.so.6")        // inject a DT_NEEDED without a parsed .so

out, err := l.Link()              // returns raw ELF bytes
```

### Architectures

| Constant | e_machine | Default interpreter |
|---|---|---|
| `ArchAMD64` | `0x3E` | `/lib64/ld-linux-x86-64.so.2` |
| `ArchARM64` | `0xB7` | `/lib/ld-linux-aarch64.so.1` |
| `ArchRISCV64` | `0xF3` | `/lib/ld-linux-riscv64-lp64d.so.1` |

### Output types

| Constant | Description |
|---|---|
| `OutputExec` | Position-dependent executable (base `0x400000`) |
| `OutputPIE` | Position-independent executable |
| `OutputShared` | Shared library (`.so`) |

---

## Parsers

Use these directly when you need parsed representations without running the full link pipeline.

```go
obj, err  := elf.ParseObject("foo.o", data)
ar,  err  := elf.ParseArchive("libfoo.a", data, elf.ParseObject)
lib, err  := elf.ParseSharedLib("libfoo.so", data)
```

`ParseArchive` accepts a `parseObject` callback so you can substitute your own
object parser. Members are parsed lazily on first access via `ArchiveMember.Object()`.

---

## Low-level pipeline

The `Linker.Link` method runs these phases in order. You can invoke them
individually if you need finer control.

```go
// 1. Parse inputs (see Parsers above)

// 2. Symbol resolution
symtab := elf.NewSymbolTable()
err = symtab.Ingest(objects, archives, shared)

// 3. Section merging
layout, err := elf.MergeSections(objects)

// 4. PLT injection (before layout)
pltSyms := elf.CollectPLTSymbols(symtab, objects)
elf.InjectPLTSections(layout, pltSyms)

// 5. Dead-code elimination
elf.GC(layout, symtab, objects, outputType, entrySymbol)

// 6. Address assignment
err = elf.AssignLayout(outputType, layout, baseVA) // baseVA=0 → default

// 7. Symbol address resolution
err = elf.ResolveSymbolAddresses(symtab, layout)

// 8. PLT patching
pp := ... // implement elf.PLTPatcher or use the internal elfPLTPatcher
elf.PatchPLT(pp, layout, pltSyms)

// 9. Relocation patching
patcher := ... // implement elf.Patcher
err = elf.PatchAll(layout, symtab, objects, patcher)

// 10. Emit
out, err := elf.Emit(&elf.EmitRequest{ ... })
```

### Key types

```go
// Layout — merged output sections with assigned addresses
type Layout struct { ... }
func (l *Layout) SectionByName(name string) (*MergedSection, bool)

// MergedSection — one output section (e.g. ".text")
type MergedSection struct {
    Name       string
    Flags      SectionFlags
    Data       []byte   // nil for BSS
    Size       uint64
    VAddr      uint64   // set by AssignLayout
    FileOffset uint64   // set by AssignLayout
}

// SymbolTable — global symbol table
func (t *SymbolTable) Lookup(name string) *TableSymbol
func (t *SymbolTable) All() []*TableSymbol

// TableSymbol
type TableSymbol struct {
    Name   string
    VAddr  uint64   // set by ResolveSymbolAddresses
    Weak   bool
    ...
}
```

---

## Builder

`Builder` lets you construct an ELF binary from scratch without a link pipeline.

```go
b := elf.NewBuilder(elf.ArchAMD64)
b.SetEntry("_start")
b.SetInterp("/lib64/ld-linux-x86-64.so.2")
b.AddNeeded("libc.so.6")

b.AddSection(elf.Section{
    Name:  ".text",
    Type:  elf.SHT_PROGBITS,
    Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR,
    Data:  codeBytes,
    Align: 16,
})
b.AddSymbol(elf.Symbol{
    Name:    "_start",
    Section: ".text",
    Global:  true,
    Type:    elf.STT_FUNC,
})

out, err := b.Emit()
```

For shared libraries: `b.SetShared()`.

---

## Note section helpers

```go
// .note.gnu.build-id
data := elf.BuildBuildID(sha1Digest)

// .note.ABI-tag  (minimum Linux kernel version)
data := elf.BuildABITag(3, 0, 0)

// .note.gnu.property  (AMD64 CET)
data := elf.BuildGNUProperty(elf.GNU_PROPERTY_X86_FEATURE_1_IBT | elf.GNU_PROPERTY_X86_FEATURE_1_SHSTK)

// arbitrary notes
data := elf.BuildNoteSection([]elf.Note{
    {Name: "GNU", Type: elf.NT_GNU_BUILD_ID, Desc: id},
})
```

---

## Dynamic linking helpers

```go
// GNU hash table for .gnu.hash
sorted, perm := elf.SortGNUHashSyms(names)
hashData := elf.BuildGNUHash(sorted, symOffset)

// SysV hash table for .hash
hashData := elf.BuildSysVHash(allSymNames) // index 0 must be ""

// .gnu.version  (SHT_GNU_VERSYM)
data := elf.BuildVersionSym([]uint16{0, 1, 2, ...})

// .gnu.version_r  (SHT_GNU_VERNEED)
data := elf.BuildVersionNeed([]elf.VersionNeed{
    {Library: "libc.so.6", Versions: []string{"GLIBC_2.17", "GLIBC_2.34"}},
}, dynstrOffsetFunc)
```

---

## Section flags

| Constant | sh_flags bit | Meaning |
|---|---|---|
| `SHF_ALLOC` | `0x2` | Occupies memory at runtime |
| `SHF_WRITE` | `0x1` | Writable |
| `SHF_EXECINSTR` | `0x4` | Executable |
| `SHF_TLS` | `0x400` | Thread-local storage |
| `SHF_MERGE` | `0x10` | Mergeable |
| `SHF_STRINGS` | `0x20` | Null-terminated strings |

Program headers `PT_PHDR`, `PT_INTERP`, `PT_LOAD`, `PT_DYNAMIC`, `PT_TLS`, and
`PT_GNU_STACK` are synthesised automatically. Use `Builder.AddSegment` for
`PT_GNU_RELRO`, `PT_NOTE`, `PT_GNU_EH_FRAME`, `PT_GNU_PROPERTY`, and any
custom entries.