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
	return os.WriteFile(path, out, mode)
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

	// Flags: ad-hoc gets CS_ADHOC|CS_LINKER_SIGNED; production drops adhoc.
	var flags uint32
	if opts.Identity == nil {
		flags = csAdhoc | csLinkerSigned
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

// pageHashes hashes each 4 KiB page of the slice over [0, codeLimit). The final
// short page is hashed over only its real bytes (no zero padding) — matching
// what codesign emits (the kernel maps the partial page the same way).
func (s *Slice) pageHashes(codeLimit int64, ht uint8) ([][]byte, error) {
	h := hashFor(ht).New()
	var out [][]byte
	for off := int64(0); off < codeLimit; off += pageSize {
		end := off + pageSize
		if end > codeLimit {
			end = codeLimit
		}
		h.Reset()
		h.Write(s.Bytes[off:end])
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