package codesign

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"
)

// OIDs used in Apple's CMS code signatures.
var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	// Apple "cdhashes as plist" signed attribute.
	oidAppleCDHashPlist = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
)

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                issuerAndSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	// content absent for detached signatures
}

type outerContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// buildCMS produces the detached CMS SignedData wrapper for a CodeDirectory.
// cdBytes is the serialised primary CodeDirectory; its message digest and a
// plist of cdhashes are carried as signed attributes.
func buildCMS(id *Identity, cdBytes []byte, cdHashes [][]byte) ([]byte, error) {
	if id == nil || id.Key == nil {
		return nil, errors.New("codesign: nil identity")
	}

	// messageDigest = SHA-256 over the CodeDirectory content.
	h := crypto.SHA256.New()
	h.Write(cdBytes)
	md := h.Sum(nil)

	plist := cdHashesPlist(cdHashes)

	// Build the signed attributes set.
	attrs := []attribute{
		rawAttr(oidContentType, mustMarshal(oidData)),
		rawAttr(oidSigningTime, mustMarshal(time.Now().UTC())),
		rawAttr(oidMessageDigest, mustMarshal(md)),
		rawAttr(oidAppleCDHashPlist, mustMarshal(plist)),
	}

	// DER of the attributes as an explicit SET OF for signing (tag 0x31),
	// per RFC 5652 §5.4 — distinct from the [0] IMPLICIT tag in the message.
	signedAttrDER, err := marshalAttrSet(attrs)
	if err != nil {
		return nil, err
	}
	ah := crypto.SHA256.New()
	ah.Write(signedAttrDER)
	digestToSign := ah.Sum(nil)

	sig, sigAlg, err := signDigest(id, digestToSign)
	if err != nil {
		return nil, err
	}

	// ... assemble signerInfo, signedData, outer ContentInfo (elided for brevity:
	// fills issuerAndSerial from id.Leaf, attaches signedAttrDER under tag:0,
	// embeds id.Leaf + intermediates in Certificates, marshals to DER) ...
	return assembleSignedData(id, md, signedAttrDER, sig, sigAlg)
}