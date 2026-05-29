# pe

Package `pe` is a self-contained PE32+ linker for AMD64 and ARM64 targets.  
It accepts COFF relocatable objects, static archives, and PE32+ DLLs and
produces a finished `.exe`, PIE, or `.dll` binary.

```
import "github.com/vertex-language/linker/pe"
```

---

## Quick start

```go
l := pe.NewLinker(pe.ArchAMD64)

// Add inputs
l.AddObject("main.obj", mainObjBytes)
l.AddArchive("libc.lib", libcBytes)
l.AddDynamicLibrary("kernel32.dll", kernel32Bytes)

// Produce binary
out, err := l.Link()
if err != nil {
    log.Fatal(err)
}
os.WriteFile("program.exe", out, 0o755)
```

---

## Linker configuration

```go
l := pe.NewLinker(pe.ArchAMD64)   // or pe.ArchARM64

l.SetOutputType(pe.OutputExec)    // default — position-dependent executable
l.SetOutputType(pe.OutputPIE)     // position-independent executable
l.SetOutputType(pe.OutputShared)  // DLL

l.SetEntryPoint("mainCRTStartup") // default; any exported symbol name
l.SetSoname("mylib.dll")          // DLL name embedded in the export directory

l.AddLibraryPath("/usr/x86_64-w64-mingw32/lib")
l.AddSONeeded("msvcrt.dll")       // explicit DT_NEEDED without an import lib
```

### Adding inputs

| Method | Accepts |
|---|---|
| `AddObject(name string, data []byte) error` | COFF `.obj` relocatable |
| `AddArchive(name string, data []byte) error` | GNU/SysV `.a` / `.lib` static archive |
| `AddDynamicLibrary(name string, data []byte) error` | PE32+ `.dll` import library |

Inputs are processed left-to-right with classical Unix archive semantics:
objects are always included; archive members are pulled in only when they
satisfy an unresolved reference.

---

## Output types

| Constant | Description |
|---|---|
| `OutputExec` | Position-dependent `.exe`; no `.reloc` section |
| `OutputPIE` | Position-independent executable; includes `.reloc` |
| `OutputShared` | `.dll`; includes `.reloc`, sets `IMAGE_FILE_DLL` |

---

## Lower-level pipeline

`Linker.Link` runs the full pipeline, but each phase is also available
individually if you need finer control.

```
ParseArchive        — parse a .a / .lib file
    ↓
NewSymbolTable / SymbolTable.Ingest
    ↓
MergeSections       — combine same-named input sections
    ↓
CollectPLTSymbols / InjectPLTSections   — DLL thunk stubs
    ↓
GC                  — dead-section elimination
    ↓
AssignLayout        — assign VAddrs and file offsets
    ↓
ResolveSymbolAddresses
    ↓
PatchPLT            — write PLT stubs into .plt / .got.plt
    ↓
PatchAll            — apply all COFF relocations
```

### Parsing archives

```go
ar, err := pe.ParseArchive("libc.lib", data, myParseObjectFn)

m := ar.MemberForSymbol("printf")   // nil if not provided
obj, err := m.Object()              // lazily parsed and cached
```

### Symbol table

```go
symtab := pe.NewSymbolTable()
err = symtab.Ingest(objects, archives, sharedLibs)

sym := symtab.Lookup("WinMain")
fmt.Println(sym.VAddr, sym.IsDefined(), sym.IsShared())
```

### Layout

```go
layout, err := pe.MergeSections(objects)

err = pe.AssignLayout(pe.OutputExec, layout, 0)   // 0 → default base

sec, ok := layout.SectionByName(".text")
fmt.Printf(".text VA=0x%x size=%d\n", sec.VAddr, sec.Size)
```

### Relocation patching

Implement `Patcher` to apply relocations yourself, or use the built-in
arch patchers via `Linker` internals.  Optionally implement
`BaseRelocCollector` to collect absolute-address sites for the `.reloc`
section.

```go
type Patcher interface {
    Apply(data []byte, off int, relType uint32, P, S uint64, A int64) error
}

type BaseRelocCollector interface {
    BaseRelocSites() []BaseRelocSite
}

err = pe.PatchAll(layout, symtab, objects, myPatcher)
```

---

## Key types

| Type | Purpose |
|---|---|
| `Linker` | Top-level orchestrator |
| `Object` | Parsed COFF relocatable (`Sections`, `Symbols`, `Relocs`) |
| `Archive` / `ArchiveMember` | Parsed static library |
| `SharedLib` / `SharedExport` | Parsed PE32+ DLL |
| `Layout` / `MergedSection` | Output section map with VAddrs |
| `SymbolTable` / `TableSymbol` | Global linker symbol table |
| `IATLayout` | DLL-grouped IAT slot assignment |
| `BaseRelocSite` | One absolute-pointer site for `.reloc` |
| `PLTEntry` | Shared symbol paired with its PLT stub index |

---

## Section flags

```go
pe.SecAlloc   // occupies memory at runtime
pe.SecWrite   // writable
pe.SecExec    // executable
pe.SecBSS     // zero-initialised, no file bytes
pe.SecTLS     // thread-local storage
```

---

## Supported architectures and relocation types

- **AMD64** — `IMAGE_FILE_MACHINE_AMD64` (`0x8664`);  
  `ADDR64`, `ADDR32`, `ADDR32NB`, `REL32`–`REL32_5`, `SECTION`, `SECREL`, `SECREL7`
- **ARM64** — `IMAGE_FILE_MACHINE_ARM64` (`0xAA64`);  
  `ADDR64`, `ADDR32`, `ADDR32NB`, `BRANCH26`, `BRANCH19`, `BRANCH14`,  
  `PAGEBASE_REL21`, `REL21`, `PAGEOFFSET_12A`, `PAGEOFFSET_12L`, `SECREL`