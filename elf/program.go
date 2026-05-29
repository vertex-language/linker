// program.go — custom PT_* segment injection API.
package elf

// The following program headers are synthesised automatically by the builder
// and must NOT be added via AddSegment:
//
//	PT_PHDR        — program header table itself
//	PT_INTERP      — set via Builder.SetInterp
//	PT_LOAD        — one per distinct permission group of SHF_ALLOC sections
//	PT_DYNAMIC     — when dynamic linking is configured
//	PT_TLS         — when any SHF_TLS section is present
//	PT_GNU_STACK   — always emitted (marks the stack non-executable)
//
// Use AddSegment for all other headers: PT_GNU_RELRO, PT_NOTE,
// PT_GNU_EH_FRAME, PT_GNU_PROPERTY, and application-specific entries.
//
// (Segment type is defined in builder.go to keep all user-facing types together.)