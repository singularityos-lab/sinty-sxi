package wire

import (
	"bytes"
	"encoding/binary"
	"sort"
)

type encoder struct {
	bytes.Buffer
}

func (e *encoder) head(major byte, value uint64) {
	switch {
	case value < 24:
		e.WriteByte(major<<5 | byte(value))
	case value <= 0xff:
		e.WriteByte(major<<5 | 24)
		e.WriteByte(byte(value))
	case value <= 0xffff:
		e.WriteByte(major<<5 | 25)
		e.Write(binary.BigEndian.AppendUint16(nil, uint16(value)))
	case value <= 0xffffffff:
		e.WriteByte(major<<5 | 26)
		e.Write(binary.BigEndian.AppendUint32(nil, uint32(value)))
	default:
		e.WriteByte(major<<5 | 27)
		e.Write(binary.BigEndian.AppendUint64(nil, value))
	}
}

func (e *encoder) uint(key, value uint64) {
	e.head(majorUnsigned, key)
	e.head(majorUnsigned, value)
}

func (e *encoder) text(key uint64, value string) {
	e.head(majorUnsigned, key)
	e.head(majorText, uint64(len(value)))
	e.WriteString(value)
}

func (e *encoder) bytesField(key uint64, value []byte) {
	e.head(majorUnsigned, key)
	e.head(majorBytes, uint64(len(value)))
	e.Write(value)
}

func (e *encoder) texts(key uint64, values []string) {
	e.head(majorUnsigned, key)
	e.head(majorArray, uint64(len(values)))
	for _, v := range values {
		e.head(majorText, uint64(len(v)))
		e.WriteString(v)
	}
}

func Encode(m *Manifest) []byte {
	var e encoder
	e.head(majorMap, 16)
	e.uint(1, 1)
	e.text(2, m.ApplicationID)
	e.text(3, m.DisplayName)
	e.text(4, m.ReleaseVersion)
	e.uint(5, m.ReleaseSequence)
	e.bytesField(6, m.PayloadDigest[:])
	e.head(majorUnsigned, 7)
	e.head(majorMap, 4)
	e.bytesField(1, m.Publisher.RootKeyID[:])
	e.bytesField(2, m.Publisher.LeafKeyID[:])
	e.uint(3, m.Publisher.DelegationEpoch)
	e.uint(4, m.Publisher.RevocationEpoch)
	e.head(majorUnsigned, 8)
	e.head(majorArray, uint64(len(m.EntryPoints)))
	for _, entry := range m.EntryPoints {
		e.head(majorMap, 4)
		e.uint(1, uint64(entry.Architecture))
		e.text(2, entry.ImagePath)
		e.uint(3, uint64(entry.Personality))
		e.head(majorUnsigned, 4)
		if entry.ABI == nil {
			e.head(majorMap, 0)
		} else {
			e.head(majorMap, 3)
			e.uint(1, uint64(entry.ABI.Epoch))
			e.uint(2, entry.ABI.Features)
			e.uint(3, entry.ABI.MinKernelBuildID)
		}
	}
	e.head(majorUnsigned, 9)
	e.head(majorArray, uint64(len(m.Inventory)))
	for _, entry := range m.Inventory {
		e.head(majorMap, 5)
		e.text(1, entry.Path)
		e.uint(2, uint64(entry.Kind))
		e.uint(3, uint64(entry.Mode))
		e.uint(4, entry.Size)
		e.bytesField(5, entry.Digest[:])
	}
	e.texts(10, m.Resources)
	e.texts(11, m.Icons)
	e.texts(12, m.Grants)
	e.texts(13, m.Portals)
	e.head(majorUnsigned, 14)
	e.head(majorMap, 3)
	e.uint(1, uint64(m.State.Current))
	e.uint(2, uint64(m.State.MinimumReadable))
	e.uint(3, uint64(m.State.MaximumReadable))
	e.head(majorUnsigned, 15)
	if m.Health.Enabled {
		e.head(majorMap, 3)
		e.uint(1, 1)
		e.text(2, m.Health.ImagePath)
		e.uint(3, uint64(m.Health.TimeoutMS))
	} else {
		e.head(majorMap, 1)
		e.uint(1, 0)
	}
	extensions := append([]Extension(nil), m.Extensions...)
	sort.Slice(extensions, func(a, b int) bool { return extensions[a].ID < extensions[b].ID })
	e.head(majorUnsigned, 16)
	e.head(majorMap, uint64(len(extensions)))
	for _, ext := range extensions {
		e.head(majorUnsigned, uint64(ext.ID))
		e.head(majorArray, 2)
		e.WriteByte(0xf4)
		e.head(majorBytes, uint64(len(ext.Value)))
		e.Write(ext.Value)
	}
	return e.Bytes()
}
