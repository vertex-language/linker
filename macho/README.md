# macho

Package `macho` is a self-contained Mach-O linker for **AMD64** and **ARM64** macOS targets. It produces position-dependent executables (`MH_EXECUTE`), position-independent executables (PIE), and shared libraries (`MH_DYLIB`) from relocatable object files, static archives, and dynamic libraries.

```go
import "github.com/vertex-language/linker/macho"
```

---

## Quick start

```go
l := macho.NewLinker(macho.ArchAMD64)
l.SetOutputType(macho.OutputExec)
l.SetEntryPoint("_main")

if err := l.AddObject("main.o", mainObjBytes); err != nil {
    log.Fatal(err)
}
if err := l.AddDynamicLibrary("libSystem.B.dylib", libSystemBytes); err != nil {
    log.Fatal(err)
}

exe, err := l.Link()
if err != nil {
    log.Fatal(err)
}
os.WriteFile("a.out", exe, 0755)
```

---

## Linker

### Creating a linker

```go
l := macho.NewLinker(arch)   // arch: macho.ArchAMD64 or macho.ArchARM64
```

### Configuration

| Method | Description |
|---|---|
| `SetOutputType(t OutputType)` | `OutputExec`, `OutputPIE`, or `OutputShared` |
| `SetEntryPoint(name string)` | Symbol name of the entry point (default `_main`) |
| `SetSoname(name string)` | Install name for dylib output |
| `SetRpath(path string)` | Embed a single `LC_RPATH` |
| `AddLibraryPath(path string)` | Search path for transitive shared library dependencies |
| `AddSONeeded(soname string)` | Force an `LC_LOAD_DYLIB` for a soname |

### Inputs

```go
l.AddObject("foo.o", data)               // relocatable object
l.AddArchive("libfoo.a", data)           // static archive (members extracted on demand)
l.AddDynamicLibrary("libbar.dylib", data) // dynamic library
```

All three methods accept raw file bytes; reading from disk is the caller's responsibility.

### Linking

```go
out, err := l.Link()
```

Returns the complete Mach-O binary as `[]byte`.

---

## Output types

```go
const (
    OutputExec   OutputType = iota // position-dependent executable (MH_EXECUTE)
    OutputPIE                      // position-independent executable (MH_EXECUTE + MH_PIE)
    OutputShared                   // shared library (MH_DYLIB)
)
```

---

## Architectures

```go
const (
    ArchAMD64 Arch = iota + 1 // x86-64
    ArchARM64                  // AArch64 / Apple Silicon
)
```

---

## Linking pipeline

`Link()` runs the following phases automatically:

1. Transitive shared-library dependency walk
2. Symbol resolution (object files → archives → dylibs, left-to-right)
3. Section merging
4. PLT / GOT stub injection for imported symbols
5. Dead-code elimination
6. Virtual address and file-offset assignment
7. Symbol address resolution
8. PLT stub patching
9. Relocation patching
10. Mach-O binary emission

---

## Static archives

Archives are linked with demand-loading semantics: a member is extracted only when it provides a definition for an otherwise-undefined symbol.

```go
l.AddArchive("libruntime.a", data)
```

If no symbol index (`/` or `__.SYMDEF`) is present, the linker falls back to scanning every member.

---

## Symbol resolution rules

- **Strong definition** beats weak; first strong wins.
- **Weak + weak**: first encountered wins.
- **Common**: largest size wins; a hard definition always overrides common.
- **Shared library** symbols fill undefined references but are overridden by any object-file definition.
- Unresolved non-weak references are a link error.

---

## Dead-code elimination

GC runs after section merging. Roots are:

- **Executables**: the entry-point symbol.
- **Dylibs**: all global non-weak exported symbols.

Sections unreachable from any root (and marked allocatable) are dropped before address assignment.

---

## Error handling

All errors are wrapped with context and returned from `Link()` (or the individual `Add*` methods). There is no internal `log` output.

```go
exe, err := l.Link()
if err != nil {
    // e.g. "link: symbol resolution: undefined reference to \"_foo\""
    log.Fatal(err)
}
```