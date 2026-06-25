# macho

Package `macho` is a self-contained Mach-O linker for **AMD64** and **ARM64**
macOS targets. It produces position-dependent executables (`MH_EXECUTE`),
position-independent executables (PIE), and shared libraries (`MH_DYLIB`) from
relocatable object files, static archives, and dynamic libraries.

Sub-package `macho/codesign` is a **standalone, from-scratch code signer** — no
`debug/macho`, no `os/exec`, no third-party libraries. It parses a finished
binary itself and writes the signature in place, so you can sign the linker's
output (or any Mach-O that already carries an `LC_CODE_SIGNATURE`) directly. It
supports both **ad-hoc** signing (`codesign --sign -`) and **production** signing
with a real certificate and CMS signature.

```go
import "github.com/vertex-language/linker/macho"
import "github.com/vertex-language/linker/macho/codesign"

```

---

## Quick start

```go
l := macho.NewLinker(macho.ArchARM64)
l.SetOutputType(macho.OutputPIE)
l.SetEntryPoint("_main")

if err := l.AddObject("main.o", mainObjBytes); err != nil {
    log.Fatal(err)
}
if err := l.AddDynamicLibrary("libSystem.B.dylib", nil); err != nil {
    log.Fatal(err)
}

exe, err := l.Link()
if err != nil {
    log.Fatal(err)
}

// Sign the finished binary in place — ad-hoc, no certificate needed.
signed, err := codesign.SignImage(exe, codesign.Options{Identifier: "a.out"})
if err != nil {
    log.Fatal(err)
}
os.WriteFile("a.out", signed, 0755)

```

> **Apple Silicon note:** `OutputExec` (non-PIE) is automatically promoted to
> PIE on ARM64 — the kernel hard-rejects non-PIE executables on that
> architecture regardless of signing. Pass `nil` as the data for
> `libSystem.B.dylib`; on macOS 12+ it lives only in the dyld shared cache and
> has no on-disk file to parse.

---

## Linker

### Creating a linker

```go
l := macho.NewLinker(arch)   // arch: macho.ArchAMD64 or macho.ArchARM64

```

### Configuration

| Method | Description |
| --- | --- |
| `SetOutputType(t OutputType)` | `OutputExec`, `OutputPIE`, or `OutputShared` |
| `SetEntryPoint(name string)` | Symbol name of the entry point (default `_main`) |
| `SetSoname(name string)` | Install name for dylib output |
| `SetRpath(path string)` | Embed a single `LC_RPATH` |
| `AddLibraryPath(path string)` | Search path for transitive shared library dependencies |
| `AddSONeeded(soname string)` | Force an `LC_LOAD_DYLIB` for a soname |

### Inputs

```go
l.AddObject("foo.o", data)                // relocatable object
l.AddArchive("libfoo.a", data)            // static archive (members extracted on demand)
l.AddDynamicLibrary("libbar.dylib", data) // dynamic library (pass nil for cache-only libs)

```

All three methods accept raw file bytes; reading from disk is the caller's
responsibility. `AddDynamicLibrary` accepts `nil` data for libraries that
exist only in the dyld shared cache (e.g. `libSystem.B.dylib` on macOS 12+).

### Linking

```go
out, err := l.Link()

```

Returns the complete Mach-O binary as `[]byte`. The linker reserves space for
the signature (an `LC_CODE_SIGNATURE` load command plus a zeroed placeholder
region at the end of `__LINKEDIT`) during emission, so the output is ready to be
handed straight to `codesign.SignImage` — see below.

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

| # | Phase |
| --- | --- |
| 1 | Transitive shared-library dependency walk |
| 2 | Symbol resolution (objects → archives → dylibs, left-to-right) |
| 3 | Section merging + PLT/GOT stub injection |
| 4 | Dead-code elimination |
| 5 | Virtual address and file-offset assignment |
| 6 | Symbol address resolution |
| 7 | PLT stub patching |
| 8 | Relocation patching |
| 9 | `LC_LOAD_DYLIB` list collection |
| 10 | Mach-O binary emission (with reserved signature space) |

The signature itself is applied as a separate step via `macho/codesign`, so it
can run after `Link()` returns or against any other finished binary.

---

## Symbol resolution rules

* **Strong definition** beats weak; first strong wins.
* **Weak + weak**: first encountered wins.
* **Common**: largest size wins; a hard definition always overrides common.
* **Shared library** symbols fill undefined references but are overridden by any object-file definition.
* Libraries present only in the dyld shared cache (passed as `nil` data) are treated as stub libraries: any still-undefined symbol is assumed to be provided by them and gets a GOT/bind entry emitted for dyld to fill at load time.
* Unresolved non-weak references are a link error.

---

## Dead-code elimination

GC runs after section merging. Roots are:

* **Executables**: the entry-point symbol.
* **Dylibs**: all global non-weak exported symbols.

Sections unreachable from any root (and marked allocatable) are dropped before
address assignment.

---

## Static archives

Archives are linked with demand-loading semantics: a member is extracted only
when it provides a definition for an otherwise-undefined symbol.

```go
l.AddArchive("libruntime.a", data)

```

Both GNU/SysV (`/`, `/SYM64/`) and BSD (`__.SYMDEF`, `__.SYMDEF_64`) symbol
index formats are supported. If no symbol index is present the linker falls
back to scanning every member.

---

## Code signing (`macho/codesign`)

macOS requires every executable to carry a code signature. On Apple Silicon
this is enforced in the kernel — an unsigned binary will not execute. On Intel
it determines Gatekeeper behaviour for locally-built binaries.

Unlike the old reserve-then-fill primitive, the package now **parses the binary
itself**. Point it at a finished Mach-O and it locates `__TEXT` and `__LINKEDIT`, reads the existing `LC_CODE_SIGNATURE`, and performs a strict two-pass update. First, it **pre-calculates the final signature size to safely patch the load commands**, then it **hashes every code page**, builds the SuperBlob, and writes it back — fat (universal) or thin, one slice or many. This ensures perfect Page 0 hash validation by Apple Mobile File Integrity (AMFI). There is no dependency on `debug/macho`, no shelling out to the real `codesign`, and no Apple-only libraries.

### The high-level API

```go
type Options struct {
    Identifier   string           // CodeDirectory ident; default: file base name
    TeamID       string           // optional team identifier
    Identity     *Identity        // nil => ad-hoc; non-nil => production CMS
    Force        bool             // overwrite an existing signature (codesign -f)
    Hardened     bool             // set CS_RUNTIME (hardened runtime)
    Entitlements []byte           // raw XML entitlements plist (optional)
    HashType     uint8            // 0 => SHA-256
    Logger       *Logger          // nil => silent at all levels
}

// Sign an in-memory image, return new bytes (fat or thin).
func SignImage(raw []byte, opts Options) ([]byte, error)

// Sign a file on disk in place. Mirrors `codesign --sign`.
// (Uses an atomic rename strategy to clear kernel vnode caches on Apple Silicon).
func SignFile(path string, opts Options) (SignResult, error)

```

### Signing the linker's output directly

Because `Link()` already reserves the `LC_CODE_SIGNATURE`, the output binary can
be signed without any further setup:

```go
exe, err := l.Link()
if err != nil {
    log.Fatal(err)
}

// Ad-hoc: no certificate, no keychain, no Developer account.
signed, err := codesign.SignImage(exe, codesign.Options{
    Identifier: "myapp",
})
if err != nil {
    log.Fatal(err)
}
os.WriteFile("myapp", signed, 0755)

```

Or sign a file that's already on disk:

```go
_, err := codesign.SignFile("./myapp", codesign.Options{Identifier: "myapp"})

```

This works on **any** Mach-O that already carries an `LC_CODE_SIGNATURE` — the
output of this linker, of `ld64`, or of the Go toolchain. Inserting a fresh
`LC_CODE_SIGNATURE` into a binary that never had one (the `codesign_allocate`
job) is intentionally out of scope; the linker reserves that space for you.

### Production signing with a certificate

Pass an `Identity` to switch from ad-hoc to a full CMS signature with a
certificate chain. Certificates and keys load from PEM (convert a `.p12` with
`openssl pkcs12` first — PKCS#12 parsing is kept out to stay pure-stdlib):

```go
id, err := codesign.LoadIdentityPEM("developer-id.pem", "developer-id.key")
if err != nil {
    log.Fatal(err)
}

ents, _ := os.ReadFile("myapp.entitlements") // XML plist

_, err = codesign.SignFile("./myapp", codesign.Options{
    Identifier:   "com.example.myapp",
    TeamID:       "ABCDE12345",
    Identity:     id,          // => CMS signature blob is added
    Hardened:     true,        // CS_RUNTIME, required for notarization
    Entitlements: ents,
    Force:        true,
})

```

With an `Identity` set, the signer drops the `CS_ADHOC` flag, emits a designated
requirement (`identifier "<id>" and anchor apple generic`), and appends a
detached CMS/PKCS#7 blob whose signed attributes carry the content type, signing
time, message digest, and Apple's `cdHashes` plist attribute.

### CLI: a `codesigner(1)` replacement

The `cmd/codesigner` binary mirrors the system tool's call shape with zero `exec`:

```sh
go install github.com/vertex-language/linker/cmd/codesigner@latest

```

```sh
# ad-hoc — equivalent to:  codesign --sign - ./main -f
codesigner --sign - -f ./main

# or straight from source, exactly as you'd run the Apple tool
go run ./macho/codesign/cmd/codesign --sign - -f ./main

# production: Developer ID, hardened runtime, entitlements
codesigner --sign "Developer ID" --cert dev.pem --key dev.key \
    -o --entitlements myapp.entitlements -f ./main

```

| Flag | Meaning |
| --- | --- |
| `--sign <id>` | `-` for ad-hoc, or an identity name/path for production |
| `--cert`, `--key` | PEM certificate (+chain) and private key for production |
| `--identifier <id>` | Explicit signing identifier (default: file base name) |
| `--team-identifier <id>` | Team identifier |
| `--entitlements <path>` | Entitlements plist (XML) |
| `-f` | Replace any existing signature |
| `-o` | Enable hardened runtime (`CS_RUNTIME`) |
| `-v`, `-vv`, `-vvv` | Verbose output levels (architecture, load commands, hashes) |

### What an ad-hoc signature contains

```
SuperBlob  (magic 0xFADE0CC0)
├── CodeDirectory  (magic 0xFADE0C02, version 0x20400)
│   ├── flags:         CS_ADHOC | CS_LINKER_SIGNED  (0x20002)
│   ├── hashType:      SHA-256
│   ├── pageSize:      4096 bytes  (log2 = 12)
│   ├── execSegBase:   __TEXT file offset
│   ├── execSegLimit:  __TEXT file size
│   ├── execSegFlags:  CS_EXECSEG_MAIN_BINARY (0x1) for executables
│   ├── identifier:    signing id C-string
│   ├── special slots: −2 Requirements  (empty set for ad-hoc)
│   └── code slots:    one SHA-256 hash per 4 KiB page
└── Requirements     (magic 0xFADE0C01, empty)

```

A production signature adds the special-slot hashes for any entitlements, a
populated Requirements blob, and a CMS wrapper:

```
SuperBlob  (magic 0xFADE0CC0)
├── CodeDirectory  (CS_RUNTIME set, CS_ADHOC cleared, teamID present)
│   ├── special slot −2: Requirements hash
│   ├── special slot −5: XML entitlements hash
│   └── special slot −7: DER entitlements hash
├── Requirements   (designated requirement)
├── Entitlements   (magic 0xFADE7171, XML plist)
├── DER Entitlements (magic 0xFADE7172)
└── CMS Wrapper    (magic 0xFADE0B01, detached PKCS#7)

```

### Flags reference

| Constant | Value | Meaning |
| --- | --- | --- |
| `CS_ADHOC` | `0x00000002` | Ad-hoc signed; no certificate |
| `CS_RUNTIME` | `0x00010000` | Hardened runtime (required for notarization) |
| `CS_LINKER_SIGNED` | `0x00020000` | Signed automatically by the linker |
| `CS_EXECSEG_MAIN_BINARY` | `0x1` | Executable segment is the main binary |

### Low-level / linker-integrated primitive

The original reserve-then-fill primitive is still exported for callers that want
to size and sign *during* emission rather than against a finished file (this is
what `builder.go` uses internally when it bakes the signature in at link time):

```go
sigSize := codesign.Size(codeSize, id)        // bytes to reserve

cmd := codesign.NewCodeSigCmd(uint32(codeSize), uint32(sigSize))
var lcBuf [16]byte
cmd.MarshalLE(lcBuf[:])                        // emit LC_CODE_SIGNATURE

codesign.Sign(
    out[codeSize:],                            // reserved zero region
    bytes.NewReader(out[:codeSize]),           // bytes being hashed
    id, int64(codeSize),
    int64(textFileOff), int64(textFileSize),
    true,                                      // isMain
)

```

Most callers should prefer `SignImage` / `SignFile`: they recover `codeSize`,
the `__TEXT` bounds, and `isMain` from the parsed file, so there are no offsets
to pass by hand.

---

## Error handling

All errors are wrapped with context and returned from `Link()` (or the
individual `Add*` methods). There is no internal `log` output.

```go
exe, err := l.Link()
if err != nil {
    // e.g. "link: symbol resolution: undefined reference to \"_foo\""
    log.Fatal(err)
}

```

Signing errors carry the slice context for fat binaries, e.g.
`codesign: slice has no LC_CODE_SIGNATURE; the linker must reserve space`.

---

## Package layout

```
macho/
├── linker.go          – Linker public API and phase orchestration
├── builder.go         – Mach-O binary emitter (segments, load commands, LINKEDIT)
├── layout.go          – Section merging and virtual address assignment
├── symtab.go          – Global symbol table and resolution
├── object.go          – Mach-O MH_OBJECT parser
├── shared.go          – Mach-O MH_DYLIB parser (export trie + LC_SYMTAB)
├── archive.go         – GNU/BSD static archive parser
├── dynamic.go         – PLT/GOT injection, bind/export trie builders
├── reloc.go           – Relocation dispatch
├── patch_amd64_macho.go – x86-64 relocation applicator
├── patch_arm64_macho.go – AArch64 relocation applicator + instruction encoders
├── gc.go              – Dead-code elimination
├── reader.go          – Bounds-checked reader, ULEB128/SLEB128 codecs
├── types.go           – Shared types (ObjectSection, Symbol, Reloc, …)
├── constants.go       – Mach-O magic numbers, load command IDs, flags
└── codesign/
    ├── doc.go            – Package documentation
    ├── blobs.go          – XNU cs_blobs.h constants (magic numbers, slot IDs, flags)
    ├── macho.go          – Mach-O reader + editor (fat & thin, in-place signing)
    ├── blob.go           – Generic blob envelope + SuperBlob assembler
    ├── codedirectory.go  – CodeDirectory builder (special slots + cdhash)
    ├── requirements.go   – Requirement-language blob encoder
    ├── entitlements.go   – XML + DER entitlement blobs
    ├── identity.go       – Signing identity (cert + key) from PEM
    ├── cms.go            – Detached CMS/PKCS#7 signature (production)
    ├── sign.go           – Options + SignImage / SignFile orchestration
    └── logger.go         – Verbose logging levels (-v, -vv, -vvv)

```