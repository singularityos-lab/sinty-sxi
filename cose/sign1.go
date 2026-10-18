package cose

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

const (
	ManifestType   = "application/vnd.six.sxi.manifest;v=1"
	DelegationType = "application/vnd.six.sxi.delegation;v=1"
	RevocationType = "application/vnd.six.sxi.revocation;v=1"
	IndexType      = "application/vnd.sinty.sxi.index+json;v=1"

	externalAAD = "SIX-SXI-SIGNATURE-v1\x00"
	tagSign1    = 18
	algEdDSA    = -8
	labelAlg    = 1
	labelType   = 3
	labelKeyID  = 4
)

var (
	ErrSignature   = errors.New("cose: signature does not verify")
	ErrContentType = errors.New("cose: unexpected content type")
	ErrKeyID       = errors.New("cose: signed by a different key")
	ErrPayload     = errors.New("cose: payload placement does not match")
)

type KeyID [sha256.Size]byte

func KeyIDOf(pub ed25519.PublicKey) KeyID {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return KeyID{}
	}
	return sha256.Sum256(der)
}

type Sign1 struct {
	Protected   []byte
	ContentType string
	KeyID       KeyID
	Payload     []byte
	Signature   []byte
}

func Parse(data []byte) (*Sign1, error) {
	if len(data) > maxStructure {
		return nil, errMalformed
	}
	r := &reader{data: data}
	if tag, err := r.expect(6); err != nil || tag != tagSign1 {
		return nil, errMalformed
	}
	if count, err := r.expect(4); err != nil || count != 4 {
		return nil, errMalformed
	}
	s := &Sign1{}
	var err error
	if s.Protected, err = r.bytesOf(2); err != nil {
		return nil, err
	}
	if err := s.parseProtected(); err != nil {
		return nil, err
	}
	if count, err := r.expect(5); err != nil || count != 0 {
		return nil, errMalformed
	}
	if r.offset < len(r.data) && r.data[r.offset] == 0xf6 {
		r.offset++
	} else if s.Payload, err = r.bytesOf(2); err != nil {
		return nil, err
	}
	if s.Signature, err = r.bytesOf(2); err != nil {
		return nil, err
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return nil, errMalformed
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Sign1) parseProtected() error {
	r := &reader{data: s.Protected}
	count, err := r.expect(5)
	if err != nil || count != 3 {
		return errMalformed
	}
	var previous []byte
	for i := uint64(0); i < count; i++ {
		l, err := r.label(previous)
		if err != nil {
			return err
		}
		previous = l.encoded
		if l.isText {
			return errMalformed
		}
		switch l.value {
		case labelAlg:
			major, value, err := r.head()
			if err != nil || major != 1 || -1-int64(value) != algEdDSA {
				return errMalformed
			}
		case labelType:
			value, err := r.bytesOf(3)
			if err != nil || len(value) == 0 {
				return errMalformed
			}
			s.ContentType = string(value)
		case labelKeyID:
			value, err := r.bytesOf(2)
			if err != nil || len(value) != len(s.KeyID) {
				return errMalformed
			}
			copy(s.KeyID[:], value)
		default:
			return errMalformed
		}
	}
	return r.done()
}

func protectedHeader(contentType string, kid KeyID) []byte {
	var w writer
	w.head(5, 3)
	w.int(labelAlg)
	w.int(algEdDSA)
	w.int(labelType)
	w.bytesValue(3, []byte(contentType))
	w.int(labelKeyID)
	w.bytesValue(2, kid[:])
	return w.Bytes()
}

func toBeSigned(protected, payload []byte) []byte {
	var w writer
	w.head(4, 4)
	w.bytesValue(3, []byte("Signature1"))
	w.bytesValue(2, protected)
	w.bytesValue(2, []byte(externalAAD))
	w.bytesValue(2, payload)
	return w.Bytes()
}

func Sign(key ed25519.PrivateKey, contentType string, payload []byte, detached bool) []byte {
	protected := protectedHeader(contentType, KeyIDOf(key.Public().(ed25519.PublicKey)))
	signature := ed25519.Sign(key, toBeSigned(protected, payload))
	var w writer
	w.head(6, tagSign1)
	w.head(4, 4)
	w.bytesValue(2, protected)
	w.head(5, 0)
	if detached {
		w.WriteByte(0xf6)
	} else {
		w.bytesValue(2, payload)
	}
	w.bytesValue(2, signature)
	return w.Bytes()
}

func (s *Sign1) Verify(key ed25519.PublicKey, contentType string, detached []byte) ([]byte, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrKeyID
	}
	if s.ContentType != contentType {
		return nil, ErrContentType
	}
	if s.KeyID != KeyIDOf(key) {
		return nil, ErrKeyID
	}
	payload := s.Payload
	if detached != nil {
		if s.Payload != nil {
			return nil, ErrPayload
		}
		payload = detached
	} else if s.Payload == nil {
		return nil, ErrPayload
	}
	if !ed25519.Verify(key, toBeSigned(s.Protected, payload), s.Signature) {
		return nil, ErrSignature
	}
	return payload, nil
}
