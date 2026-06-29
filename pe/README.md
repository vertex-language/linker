# pe

Package `pe` is a self-contained PE32+ linker for AMD64 and ARM64 targets.
It accepts COFF relocatable objects, static archives, and PE32+ DLLs and
produces a finished `.exe`, PIE, or `.dll` binary.

```go
import "github.com/vertex-language/linker/pe"
```

---

## Quick start

```go
l := pe.NewLinker(pe.ArchAMD64)

l.AddObject("main.obj", mainObjBytes)
l.AddArchive("libc.lib", libcBytes)
l.AddDynamicLibrary("kernel32.dll", kernel32Bytes)

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
| `OutputExec` | Position-dependent `.exe`; no `.reloc` section; `IMAGE_FILE_RELOCS_STRIPPED` set |
| `OutputPIE` | Position-independent executable; `.reloc` section emitted when absolute pointers exist |
| `OutputShared` | `.dll`; `.reloc` emitted; `IMAGE_FILE_DLL` set |

`DYNAMIC_BASE` and `HIGH_ENTROPY_VA` are advertised in `DllCharacteristics`
only when a `.reloc` section was actually produced. `NX_COMPAT` and
`TERMINAL_SERVER_AWARE` are always set.

---

## Link pipeline

`Linker.Link` runs the following phases in order. Each phase is also
exported individually for lower-level use.

```
AddObject / AddArchive / AddDynamicLibrary
    ↓
walkSharedDeps          — transitive DLL dependency walk
                          (api-ms-win-* / ext-ms-win-* API Sets are skipped)
    ↓
SymbolTable.Ingest      — symbol resolution (objects → shared → archives)
    ↓
MergeSections           — combine same-named input sections
    ↓
CollectPLTSymbols       — find shared symbols referenced by object relocations
    ↓
GC                      — dead-section elimination from entry point or exports
    ↓
InjectPLTSections       — append synthetic .plt / .got.plt / .rela.plt
    ↓
AssignLayout            — assign VAddrs and file offsets
    ↓
ResolveSymbolAddresses  — fill VAddr on every defined symbol
    ↓
PatchPLT                — write import thunk stubs; assign stub VAddrs
    ↓
PatchAll                — apply all COFF relocations
    ↓
emitPE                  — serialise DOS stub, COFF/optional headers,
                          section headers, .idata, .reloc, and section data
```

---

## Dead-code elimination (GC)

`GC` performs reachability analysis before address assignment, removing
unreachable `SHF_ALLOC` sections to reduce output size.

- For executables and PIEs the root is the entry-point symbol.
- For DLLs all globally-exported defined symbols are roots.
- Non-allocatable sections (debug info, etc.) are always kept.
- `.pdata` and `.xdata` (Windows x64 SEH tables) are unconditionally
  kept because they are required by the OS loader but are never directly
  referenced by code relocations.

Synthetic PLT/GOT/RELA sections are injected **after** GC so they are
never subject to elimination.

---

## Import thunks (PLT / IAT)

For each shared symbol referenced by an object relocation the linker
generates a 16-byte import thunk in `.plt` and an IAT slot in `.got.plt`.
Slots are grouped by DLL with a null-terminator entry between groups so
the Windows loader can walk them as a standard IAT.

The `.idata` section (PE import directory) is built from that layout
during `emitPE` and is placed after all core sections at the next
section-alignment boundary.

**AMD64** thunks use an indirect `jmp [rip + rel32]` through the IAT slot.  
**ARM64** thunks use an `adrp` / `ldr` / `br` sequence through register `x17`.

---

## Base relocations

The AMD64 and ARM64 patchers implement `BaseRelocCollector`. After
`PatchAll`, every site where an absolute 64-bit pointer was written is
collected and passed to `buildBaseRelocSection`, which groups them into
the page-block format expected by the NT loader and emits them as `.reloc`.

---

## Lower-level API

### Parsing archives

```go
ar, err := pe.ParseArchive("libc.lib", data, parseObject)

m := ar.MemberForSymbol("printf")  // nil if not provided
obj, err := m.Object()             // lazily parsed and cached
```

Supports GNU/SysV 32-bit (`/`) and 64-bit (`/SYM64/`) symbol tables, BSD
`__.SYMDEF` / `__.SYMDEF_64`, long-name tables (`//`), and falls back to
an exhaustive scan when no symbol table is present.

### Symbol table

```go
symtab := pe.NewSymbolTable()
err = symtab.Ingest(objects, archives, sharedLibs)

sym := symtab.Lookup("WinMain")
fmt.Println(sym.VAddr, sym.IsDefined(), sym.IsShared())
```

Resolution precedence: strong definition beats weak; defined beats common
(larger common wins between two commons); hard definition beats common.
Unresolved strong references from object files produce an error.

### Layout

```go
layout, err := pe.MergeSections(objects)
err = pe.AssignLayout(pe.OutputExec, layout, 0)  // 0 → default base VA

sec, ok := layout.SectionByName(".text")
fmt.Printf(".text VA=0x%x size=%d\n", sec.VAddr, sec.Size)
```

Sections are grouped into three `PT_LOAD`-equivalent segments (RX, RO, RW)
and must tile contiguously in virtual address space — the NT loader rejects
any RVA gap with `ERROR_BAD_EXE_FORMAT`. Each section's VAddr is advanced
by its page-rounded size to satisfy this constraint.

### Relocation patching

```go
type Patcher interface {
    Apply(data []byte, off int, relType uint32, P, S uint64, A int64) error
}

// Optional — collect sites for .reloc
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
| `Archive` / `ArchiveMember` | Parsed static library; members lazily parsed and cached |
| `SharedLib` / `SharedExport` | Parsed PE32+ DLL and its export table |
| `Layout` / `MergedSection` | Output section map with assigned VAddrs and file offsets |
| `SymbolTable` / `TableSymbol` | Global linker symbol table |
| `IATLayout` | DLL-grouped IAT slot assignment used to build `.idata` |
| `PLTEntry` | Shared symbol paired with its 0-based PLT stub index |
| `BaseRelocSite` | One absolute-pointer VA for `.reloc` |
| `EmitRequest` | All post-link data passed to the PE serialiser |

---

## Section flags

```go
pe.SecAlloc  // occupies memory at runtime
pe.SecWrite  // writable
pe.SecExec   // executable
pe.SecBSS    // zero-initialised; no file bytes
pe.SecTLS    // thread-local storage
```

---

## Supported architectures and relocation types

**AMD64** — `IMAGE_FILE_MACHINE_AMD64` (`0x8664`)

`ABSOLUTE`, `ADDR64`, `ADDR32`, `ADDR32NB`, `REL32`, `REL32_1`–`REL32_5`,
`SECTION`, `SECREL`, `SECREL7`, `TOKEN`

**ARM64** — `IMAGE_FILE_MACHINE_ARM64` (`0xAA64`)

`ABSOLUTE`, `ADDR32`, `ADDR32NB`, `ADDR64`, `BRANCH26`, `BRANCH19`,
`BRANCH14`, `PAGEBASE_REL21`, `REL21`, `PAGEOFFSET_12A`, `PAGEOFFSET_12L`,
`SECREL`, `SECREL_LOW12A`, `SECREL_HIGH12A`, `SECREL_LOW12L`,
`SECTION`, `TOKEN`, `REL32`

> AMD64 and ARM64 share several numeric type values (e.g. both define type
> `1`). The patcher branches on machine type before switching on relocation
> type to avoid ambiguity.

---

## PE output layout

```
0x000          DOS stub (64 bytes) + PE signature
0x044          COFF header
0x058          PE32+ optional header (240 bytes)
               └─ data directories: Import, Exception (.pdata),
                  Base Reloc, IAT
               Section headers (40 bytes × n)
0x200 (align)  Section data  [RX → RO → RW]
               .idata         (import directory, built by emitter)
               .reloc         (base relocations, PIE/DLL only)
```

Minimum supported Windows version: **Windows 7** (MajorOS/SubsystemVersion 6.1).