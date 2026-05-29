# linker

`linker` is a pure-Go linker toolkit for producing native binaries across the three major object-file ecosystems. Each sub-package is self-contained and shares no runtime dependencies with the others.

| Sub-package | Object format | Output formats | Architectures |
|---|---|---|---|
| [`linker/elf`](./elf) | ELF64 | Executable, PIE, Shared (`.so`) | AMD64, ARM64, RISC-V 64 |
| [`linker/pe`](./pe) | PE32+ / COFF | Executable, PIE, DLL (`.dll`) | AMD64, ARM64 |
| [`linker/macho`](./macho) | Mach-O | Executable, PIE, Dylib (`.dylib`) | AMD64, ARM64 |

---

## Installation

```
go get github.com/vertex-language/linker
```

Import only the sub-package(s) you need:

```go
import "github.com/vertex-language/linker/elf"
import "github.com/vertex-language/linker/pe"
import "github.com/vertex-language/linker/macho"
```

---

## Quick start

All three linkers expose the same high-level pattern: create a linker for a
target architecture, add inputs, call `Link()`.

**ELF (Linux)**

```go
l := elf.NewLinker(elf.ArchAMD64)
l.AddObject("main.o", mainBytes)
l.AddArchive("libc.a", libcBytes)
l.AddDynamicLibrary("libc.so.6", libcSOBytes)
out, err := l.Link()
```

**PE (Windows)**

```go
l := pe.NewLinker(pe.ArchAMD64)
l.AddObject("main.obj", mainObjBytes)
l.AddArchive("libc.lib", libcBytes)
l.AddDynamicLibrary("kernel32.dll", kernel32Bytes)
out, err := l.Link()
```

**Mach-O (macOS)**

```go
l := macho.NewLinker(macho.ArchAMD64)
l.AddObject("main.o", mainObjBytes)
l.AddDynamicLibrary("libSystem.B.dylib", libSystemBytes)
out, err := l.Link()
```

---

## Common concepts

Despite targeting different formats, all three sub-packages share the same
design philosophy.

### Input types

Each linker accepts the same three classes of input:

| Method | Accepts |
|---|---|
| `AddObject(name, data)` | Relocatable object file |
| `AddArchive(name, data)` | Static archive; members are demand-loaded |
| `AddDynamicLibrary(name, data)` | Shared library / import library |

Inputs are processed left-to-right with classical Unix archive semantics:
object files are always included; archive members are pulled in only when they
satisfy an unresolved reference.

### Output types

| Constant | Description |
|---|---|
| `OutputExec` | Position-dependent executable |
| `OutputPIE` | Position-independent executable (includes relocation table) |
| `OutputShared` | Shared library / DLL (includes relocation table) |

### Symbol resolution

All three linkers follow the same precedence rules:

- Strong definition beats weak; first strong definition wins.
- Weak + weak: first encountered wins.
- Common symbols: largest size wins; a hard definition always overrides common.
- Shared-library symbols fill undefined references but are overridden by any
  object-file definition.
- Unresolved non-weak references are a link error.

### Dead-code elimination

Each linker runs a GC phase after section merging. Roots are the entry-point
symbol for executables and all non-weak exported symbols for shared libraries.
Allocatable sections unreachable from any root are dropped before address
assignment.

### Linking pipeline

All three linkers execute the same logical phases:

```
Parse inputs
    ↓
Symbol resolution
    ↓
Section merging
    ↓
PLT / GOT / thunk stub injection
    ↓
Dead-code elimination (GC)
    ↓
Address assignment (VAddr + file offsets)
    ↓
Symbol address resolution
    ↓
PLT stub patching
    ↓
Relocation patching
    ↓
Binary emission
```

`Link()` runs all phases end-to-end. Each phase is also exported individually
for tooling that needs finer control — see the sub-package documentation for
details.

### Error handling

All errors are wrapped with context and returned from `Link()` or the `Add*`
methods. None of the sub-packages write to `log` or `os.Stderr`.

```go
out, err := l.Link()
if err != nil {
    log.Fatal(err) // e.g. "link: symbol resolution: undefined reference to \"_foo\""
}
```

---

## Architecture support

| Architecture | ELF | PE | Mach-O |
|---|---|---|---|
| AMD64 (x86-64) | ✓ | ✓ | ✓ |
| ARM64 (AArch64) | ✓ | ✓ | ✓ |
| RISC-V 64 | ✓ | — | — |

---

## Sub-package documentation

- **[linker/elf](./elf)** — ELF64 linker. Also exposes a `Builder` for
  constructing ELF binaries from scratch, plus helpers for GNU hash tables,
  version sections, and note sections.
- **[linker/pe](./pe)** — PE32+ / COFF linker. Supports the full set of AMD64
  and ARM64 COFF relocation types.
- **[linker/macho](./macho)** — Mach-O linker. Handles transitive dylib
  dependency walking and `LC_RPATH` / `LC_LOAD_DYLIB` load-command emission.