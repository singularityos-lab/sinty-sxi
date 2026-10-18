package wire

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	payloadDomain     = "SIX-SXI-PAYLOAD-v1\x00"
	slotDomain        = "SIX-SXI-SLOT-v1\x00"
	publisherDomain   = "SIX-SXI-PUBLISHER-v1\x00"
	applicationDomain = "SIX-SXI-APP-v1\x00"
	releaseDomain     = "SIX-SXI-RELEASE-v1\x00"
)

func InventoryRecords(domain string, entries []Entry) []byte {
	out := append([]byte(domain), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(out[len(domain):], uint32(len(entries)))
	for _, e := range entries {
		out = binary.BigEndian.AppendUint16(out, uint16(len(e.Path)))
		out = append(out, e.Path...)
		out = append(out, byte(e.Kind))
		out = binary.BigEndian.AppendUint16(out, e.Mode)
		out = binary.BigEndian.AppendUint64(out, e.Size)
		out = append(out, e.Digest[:]...)
	}
	return out
}

func PayloadDigestOf(entries []Entry) [DigestSize]byte {
	return sha256.Sum256(InventoryRecords(payloadDomain, entries))
}

func SlotID(entries []Entry) [DigestSize]byte {
	return sha256.Sum256(InventoryRecords(slotDomain, entries))
}

func PublisherIdentity(rootKeyID [DigestSize]byte) [DigestSize]byte {
	return sha256.Sum256(append([]byte(publisherDomain), rootKeyID[:]...))
}

func ApplicationIdentity(publisher [DigestSize]byte, applicationID string) [DigestSize]byte {
	out := append([]byte(applicationDomain), publisher[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(applicationID)))
	return sha256.Sum256(append(out, applicationID...))
}

func ReleasePreimage(manifest []byte) []byte {
	out := binary.BigEndian.AppendUint32([]byte(releaseDomain), uint32(len(manifest)))
	return append(out, manifest...)
}

func ReleaseID(manifest []byte) [DigestSize]byte {
	return sha256.Sum256(ReleasePreimage(manifest))
}
