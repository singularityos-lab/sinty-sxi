package trust

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/singularityos-lab/sinty-sxi/cose"
)

const (
	PurposeRelease = "release"
	PurposeIndex   = "index"
)

var errRecord = errors.New("trust: malformed record")

type Delegation struct {
	Key       ed25519.PublicKey
	Epoch     uint64
	NotBefore uint64
	NotAfter  uint64
	Purposes  []string
}

type Revocation struct {
	Epoch                  uint64
	MinimumDelegationEpoch uint64
	RevokedKeys            []cose.KeyID
}

type cbor struct {
	bytes.Buffer
}

func (c *cbor) head(major byte, value uint64) {
	switch {
	case value < 24:
		c.WriteByte(major<<5 | byte(value))
	case value <= 0xff:
		c.WriteByte(major<<5 | 24)
		c.WriteByte(byte(value))
	case value <= 0xffff:
		c.WriteByte(major<<5 | 25)
		c.Write(binary.BigEndian.AppendUint16(nil, uint16(value)))
	case value <= 0xffffffff:
		c.WriteByte(major<<5 | 26)
		c.Write(binary.BigEndian.AppendUint32(nil, uint32(value)))
	default:
		c.WriteByte(major<<5 | 27)
		c.Write(binary.BigEndian.AppendUint64(nil, value))
	}
}

func (c *cbor) raw(major byte, value []byte) {
	c.head(major, uint64(len(value)))
	c.Write(value)
}

type parser struct {
	data   []byte
	offset int
}

func (p *parser) head() (byte, uint64, error) {
	if p.offset >= len(p.data) {
		return 0, 0, errRecord
	}
	initial := p.data[p.offset]
	p.offset++
	major, additional := initial>>5, initial&0x1f
	if additional < 24 {
		return major, uint64(additional), nil
	}
	if additional > 27 {
		return 0, 0, errRecord
	}
	size := 1 << (additional - 24)
	if size > len(p.data)-p.offset {
		return 0, 0, errRecord
	}
	var value uint64
	for i := 0; i < size; i++ {
		value = value<<8 | uint64(p.data[p.offset])
		p.offset++
	}
	if (size == 1 && value < 24) || (size == 2 && value <= 0xff) ||
		(size == 4 && value <= 0xffff) || (size == 8 && value <= 0xffffffff) || major == 7 {
		return 0, 0, errRecord
	}
	return major, value, nil
}

func (p *parser) expect(major byte) (uint64, error) {
	got, value, err := p.head()
	if err != nil || got != major {
		return 0, errRecord
	}
	return value, nil
}

func (p *parser) raw(major byte) ([]byte, error) {
	length, err := p.expect(major)
	if err != nil || length > uint64(len(p.data)-p.offset) {
		return nil, errRecord
	}
	out := p.data[p.offset : p.offset+int(length)]
	p.offset += int(length)
	return out, nil
}

func (p *parser) fields(count uint64, field func(key uint64) error) error {
	for want := uint64(1); want <= count; want++ {
		key, err := p.expect(0)
		if err != nil || key != want {
			return errRecord
		}
		if err := field(key); err != nil {
			return err
		}
	}
	if p.offset != len(p.data) {
		return errRecord
	}
	return nil
}

func EncodeDelegation(d *Delegation) []byte {
	purposes := append([]string(nil), d.Purposes...)
	sort.Strings(purposes)
	var c cbor
	c.head(5, 5)
	c.head(0, 1)
	c.raw(2, d.Key)
	c.head(0, 2)
	c.head(0, d.Epoch)
	c.head(0, 3)
	c.head(0, d.NotBefore)
	c.head(0, 4)
	c.head(0, d.NotAfter)
	c.head(0, 5)
	c.head(4, uint64(len(purposes)))
	for _, p := range purposes {
		c.raw(3, []byte(p))
	}
	return c.Bytes()
}

func ParseDelegation(data []byte) (*Delegation, error) {
	p := &parser{data: data}
	if count, err := p.expect(5); err != nil || count != 5 {
		return nil, errRecord
	}
	d := &Delegation{}
	err := p.fields(5, func(key uint64) error {
		var err error
		switch key {
		case 1:
			var key []byte
			if key, err = p.raw(2); err != nil || len(key) != ed25519.PublicKeySize {
				return errRecord
			}
			d.Key = append(ed25519.PublicKey(nil), key...)
		case 2:
			d.Epoch, err = p.expect(0)
		case 3:
			d.NotBefore, err = p.expect(0)
		case 4:
			d.NotAfter, err = p.expect(0)
		case 5:
			var count uint64
			if count, err = p.expect(4); err != nil || count == 0 || count > 8 {
				return errRecord
			}
			for i := uint64(0); i < count; i++ {
				value, err := p.raw(3)
				if err != nil {
					return err
				}
				name := string(value)
				if name != PurposeRelease && name != PurposeIndex {
					return errRecord
				}
				if len(d.Purposes) > 0 && d.Purposes[len(d.Purposes)-1] >= name {
					return errRecord
				}
				d.Purposes = append(d.Purposes, name)
			}
		}
		return err
	})
	if err != nil {
		return nil, errRecord
	}
	if d.NotAfter <= d.NotBefore {
		return nil, errRecord
	}
	return d, nil
}

func (d *Delegation) Allows(purpose string) bool {
	for _, p := range d.Purposes {
		if p == purpose {
			return true
		}
	}
	return false
}

func EncodeRevocation(r *Revocation) []byte {
	keys := append([]cose.KeyID(nil), r.RevokedKeys...)
	sort.Slice(keys, func(a, b int) bool { return bytes.Compare(keys[a][:], keys[b][:]) < 0 })
	var c cbor
	c.head(5, 3)
	c.head(0, 1)
	c.head(0, r.Epoch)
	c.head(0, 2)
	c.head(0, r.MinimumDelegationEpoch)
	c.head(0, 3)
	c.head(4, uint64(len(keys)))
	for _, k := range keys {
		c.raw(2, k[:])
	}
	return c.Bytes()
}

func ParseRevocation(data []byte) (*Revocation, error) {
	p := &parser{data: data}
	if count, err := p.expect(5); err != nil || count != 3 {
		return nil, errRecord
	}
	r := &Revocation{}
	err := p.fields(3, func(key uint64) error {
		var err error
		switch key {
		case 1:
			r.Epoch, err = p.expect(0)
		case 2:
			r.MinimumDelegationEpoch, err = p.expect(0)
		case 3:
			var count uint64
			if count, err = p.expect(4); err != nil || count > 4096 {
				return errRecord
			}
			for i := uint64(0); i < count; i++ {
				value, err := p.raw(2)
				if err != nil || len(value) != len(cose.KeyID{}) {
					return errRecord
				}
				var id cose.KeyID
				copy(id[:], value)
				if len(r.RevokedKeys) > 0 && bytes.Compare(r.RevokedKeys[len(r.RevokedKeys)-1][:], id[:]) >= 0 {
					return errRecord
				}
				r.RevokedKeys = append(r.RevokedKeys, id)
			}
		}
		return err
	})
	if err != nil {
		return nil, errRecord
	}
	return r, nil
}

func (r *Revocation) Revoked(id cose.KeyID) bool {
	for _, k := range r.RevokedKeys {
		if k == id {
			return true
		}
	}
	return false
}
