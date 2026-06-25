package codesign

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Options is the clean, codesign-inspired surface.
type Options struct {
	Identifier   string    // CodeDirectory ident; default: file base name
	TeamID       string    // optional team identifier
	Identity     *Identity // nil => ad-hoc; non-nil => production CMS
	Force        bool      // overwrite an existing signature (codesign -f)
	Hardened     bool      // set CS_RUNTIME
	Entitlements []byte    // raw XML entitlements plist (optional)
	HashType     uint8     // 0 => SHA-256
}

// SignFile signs the Mach-O at path in place. It mirrors `codesign --sign`.
//
// The updated binary is written to a sibling temp file and then renamed into
// place.  This is critical on Apple Silicon: the kernel caches code signatures
// per vnode.  Overwriting the file in-place (same inode) can leave the kernel
// serving the stale cached signature from a previous failed execution.
// rename(2) replaces the directory entry atomically and forces the kernel to
// evaluate the new signature on the next exec — the same technique used
// internally by codesign_allocate.
func SignFile(path string, opts Options) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if opts.Identifier == "" {
		opts.Identifier = filepath.Base(path)
	}
	out, err := SignImage(raw, opts)
	if err != nil {
		return err
	}

	info, _ := os.Stat(path)
	mode := os.FileMode(0o755)
	if info != nil {
		mode = info.Mode()
	}

	tmp := path + ".__codesign_tmp"
	if err := os.WriteFile(tmp, out, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// SignImage signs every slice of a (fat or thin) image and returns new bytes.
func SignImage(raw []byte, opts Options) ([]byte, error) {
	img, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	for _, sl := range img.Slices {
		if !sl.hasReservedSignatureSpace() && !opts.Force {
			return nil, fmt.Errorf("codesign: slice has no LC_CODE_SIGNATURE; "+
				"the linker must reserve space (re-link, or use -f to allow rewrite)")
		}
		if err := signSlice(sl, opts); err != nil {
			return nil, err
		}
	}
	return img.serialize()
}

func (s *Slice) hashType(opts Options) uint8 {
	if opts.HashType != 0 {
		return opts.HashType
	}
	return csHashTypeSHA256
}

// signSlice computes hashes, builds the SuperBlob, and writes it into the slice.
func signSlice(s *Slice, opts Options) error {
	ht := s.hashType(opts)
	codeLimit := s.signatureRegionStart()

	// Flags: ad-hoc signing uses CS_ADHOC only.
	//
	// CS_LINKER_SIGNED must NOT be set here.  It is only valid for the
	// minimal linker-emitted signature (nSpecialSlots=0, no Requirements
	// blob, single CodeDirectory).  This tool produces a full codesign-style
	// layout that always includes a Requirements blob (nSpecialSlots >= 2).
	// Mixing CS_LINKER_SIGNED with that structure causes the kernel to reject
	// the binary with SIGKILL.  Apple's codesign --sign - sets CS_ADHOC only.
	var flags uint32
	if opts.Identity == nil {
		flags = csAdhoc
	}
	if opts.Hardened {
		flags |= csRuntime
	}

	var execFlags uint64
	if s.isMain {
		execFlags = csExecSegMainBinary
	}

	// --- assemble component blobs and their special-slot hashes ---
	special := map[int][]byte{}
	var components []blob

	// Requirements (-2)
	var reqs []byte
	if opts.Identity != nil {
		reqs = designatedRequirement(opts.Identifier)
	} else {
		reqs = emptyRequirements()
	}
	components = append(components, blob{slot: csslotRequirements, data: reqs})
	special[2] = hashBlob(reqs, ht)

	// Entitlements (-5, and DER -7 when present)
	if len(opts.Entitlements) > 0 {
		ent := xmlEntitlements(opts.Entitlements)
		components = append(components, blob{slot: csslotEntitlements, data: ent})
		special[5] = hashBlob(ent, ht)
	}

	// --- code (page) hashes over [0, codeLimit) ---
	codeHashes, err := s.pageHashes(codeLimit, ht)
	if err != nil {
		return err
	}

	cd := buildCodeDirectory(cdParams{
		identifier:    opts.Identifier,
		teamID:        opts.TeamID,
		flags:         flags,
		hashType:      ht,
		pageBits:      pageSizeBits,
		codeLimit:     codeLimit,
		execBase:      s.textOff,
		execLimit:     s.textSize,
		execFlags:     execFlags,
		codeHashes:    codeHashes,
		specialHashes: special,
	})
	primary := blob{slot: csslotCodeDirectory, data: cd}

	all := append([]blob{primary}, components...)

	// Production: append CMS signature blob.
	if opts.Identity != nil {
		cms, err := buildCMS(opts.Identity, cd, [][]byte{cdHash(cd, ht)})
		if err != nil {
			return err
		}
		all = append(all, blob{slot: csslotSignature, data: cms})
	}

	sortBlobs(all)
	super := assembleSuperBlob(all)

	return s.embedSignature(super, codeLimit)
}

// pageHashes hashes each 4 KiB page of the slice over [0, codeLimit).
//
// Each page is hashed over exactly its real bytes.  For full pages that is
// 4096 bytes; for the final short page it is (codeLimit % pageSize) bytes
// only.  This matches Apple's codesign, the Darwin linker, and the Go
// toolchain — all hash the actual bytes, never zero-padded to a full page.
func (s *Slice) pageHashes(codeLimit int64, ht uint8) ([][]byte, error) {
	h := hashFor(ht).New()
	var out [][]byte
	for off := int64(0); off < codeLimit; off += pageSize {
		end := off + pageSize
		if end > codeLimit {
			end = codeLimit
		}
		h.Reset()
		h.Write(s.Bytes[off:end]) // exact bytes only; no zero padding
		out = append(out, h.Sum(nil))
	}
	return out, nil
}

func hashBlob(b []byte, ht uint8) []byte {
	h := hashFor(ht).New()
	h.Write(b)
	return h.Sum(nil)
}

var _ = sha256.Size
var _ = errors.New