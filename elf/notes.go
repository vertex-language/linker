// notes.go — GNU ELF note section builders.
package elf

import "encoding/binary"

// BuildNoteSection serialises a slice of Notes into a SHT_NOTE section body.
func BuildNoteSection(notes []Note) []byte {
	var buf []byte
	for _, n := range notes {
		namez := append([]byte(n.Name), 0)
		namesz := uint32(len(namez))
		descsz := uint32(len(n.Desc))
		var hdr [12]byte
		binary.LittleEndian.PutUint32(hdr[0:], namesz)
		binary.LittleEndian.PutUint32(hdr[4:], descsz)
		binary.LittleEndian.PutUint32(hdr[8:], n.Type)
		buf = append(buf, hdr[:]...)
		buf = notePad4(buf, namez)
		buf = notePad4(buf, n.Desc)
	}
	return buf
}

// Note is a single ELF note entry (Elf64_Nhdr + name + desc).
type Note struct {
	Name string
	Type uint32
	Desc []byte
}

// BuildBuildID returns a .note.gnu.build-id section body.
// id is the raw identifier — typically a SHA-1 digest (20 bytes) or UUID (16 bytes).
func BuildBuildID(id []byte) []byte {
	return BuildNoteSection([]Note{{Name: "GNU", Type: NT_GNU_BUILD_ID, Desc: id}})
}

// BuildABITag returns a .note.ABI-tag section body declaring the minimum Linux
// kernel ABI version required. Example: major=2, minor=6, patch=32.
func BuildABITag(major, minor, patch uint32) []byte {
	desc := make([]byte, 16)
	binary.LittleEndian.PutUint32(desc[0:], GNU_ABI_TAG_LINUX)
	binary.LittleEndian.PutUint32(desc[4:], major)
	binary.LittleEndian.PutUint32(desc[8:], minor)
	binary.LittleEndian.PutUint32(desc[12:], patch)
	return BuildNoteSection([]Note{{Name: "GNU", Type: NT_GNU_ABI_TAG, Desc: desc}})
}

// BuildGNUProperty returns a .note.gnu.property section body for AMD64 CET.
// featureFlags is a bitmask of GNU_PROPERTY_X86_FEATURE_1_* values.
func BuildGNUProperty(featureFlags uint32) []byte {
	desc := make([]byte, 16)
	binary.LittleEndian.PutUint32(desc[0:], GNU_PROPERTY_X86_FEATURE_1_AND)
	binary.LittleEndian.PutUint32(desc[4:], 4) // pr_datasz
	binary.LittleEndian.PutUint32(desc[8:], featureFlags)
	return BuildNoteSection([]Note{{Name: "GNU", Type: NT_GNU_PROPERTY, Desc: desc}})
}

func notePad4(buf, data []byte) []byte {
	buf = append(buf, data...)
	if r := len(buf) % 4; r != 0 {
		buf = append(buf, make([]byte, 4-r)...)
	}
	return buf
}