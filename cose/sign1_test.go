package cose

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func newKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestDetachedRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	payload := []byte("manifest bytes")
	s, err := Parse(Sign(priv, ManifestType, payload, true))
	if err != nil {
		t.Fatal(err)
	}
	if s.Payload != nil {
		t.Fatal("detached signature carries a payload")
	}
	if _, err := s.Verify(pub, ManifestType, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(pub, ManifestType, []byte("other bytes")); !errors.Is(err, ErrSignature) {
		t.Fatalf("changed payload: %v", err)
	}
	if _, err := s.Verify(pub, ManifestType, nil); !errors.Is(err, ErrPayload) {
		t.Fatalf("missing detached payload: %v", err)
	}
}

func TestAttachedRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	s, err := Parse(Sign(priv, DelegationType, []byte{0xa0}, false))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := s.Verify(pub, DelegationType, nil)
	if err != nil || !bytes.Equal(payload, []byte{0xa0}) {
		t.Fatalf("payload %x, %v", payload, err)
	}
	if _, err := s.Verify(pub, DelegationType, []byte{0xa0}); !errors.Is(err, ErrPayload) {
		t.Fatalf("attached payload accepted as detached: %v", err)
	}
}

func TestWrongKeyAndType(t *testing.T) {
	_, priv := newKey(t)
	other, _ := newKey(t)
	s, err := Parse(Sign(priv, ManifestType, []byte("x"), true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(other, ManifestType, []byte("x")); !errors.Is(err, ErrKeyID) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := s.Verify(priv.Public().(ed25519.PublicKey), IndexType, []byte("x")); !errors.Is(err, ErrContentType) {
		t.Fatalf("other type: %v", err)
	}
}

func TestTamperedBytes(t *testing.T) {
	pub, priv := newKey(t)
	payload := []byte("manifest")
	good := Sign(priv, ManifestType, payload, true)
	for i := range good {
		for _, bit := range []byte{0x01, 0x80} {
			bad := append([]byte(nil), good...)
			bad[i] ^= bit
			s, err := Parse(bad)
			if err != nil {
				continue
			}
			if _, err := s.Verify(pub, ManifestType, payload); err == nil {
				t.Fatalf("flipping byte %d bit %#x still verifies", i, bit)
			}
		}
	}
}

func TestStrictStructure(t *testing.T) {
	_, priv := newKey(t)
	good := Sign(priv, ManifestType, []byte("m"), true)
	kid := KeyIDOf(priv.Public().(ed25519.PublicKey))
	header := func(build func(w *writer)) []byte {
		var w writer
		build(&w)
		return w.Bytes()
	}
	envelope := func(protected []byte, unprotected []byte) []byte {
		var w writer
		w.head(6, tagSign1)
		w.head(4, 4)
		w.bytesValue(2, protected)
		w.Write(unprotected)
		w.WriteByte(0xf6)
		w.bytesValue(2, make([]byte, 64))
		return w.Bytes()
	}
	cases := map[string][]byte{
		"untagged":           good[1:],
		"trailing":           append(append([]byte(nil), good...), 0x00),
		"truncated":          good[:len(good)-1],
		"unprotected header": envelope(protectedHeader(ManifestType, kid), []byte{0xa1, 0x04, 0x40}),
		"extra label": envelope(header(func(w *writer) {
			w.head(5, 4)
			w.int(labelAlg)
			w.int(algEdDSA)
			w.int(2)
			w.head(4, 0)
			w.int(labelType)
			w.bytesValue(3, []byte(ManifestType))
			w.int(labelKeyID)
			w.bytesValue(2, kid[:])
		}), []byte{0xa0}),
		"other algorithm": envelope(header(func(w *writer) {
			w.head(5, 3)
			w.int(labelAlg)
			w.int(-7)
			w.int(labelType)
			w.bytesValue(3, []byte(ManifestType))
			w.int(labelKeyID)
			w.bytesValue(2, kid[:])
		}), []byte{0xa0}),
		"unordered labels": envelope(header(func(w *writer) {
			w.head(5, 3)
			w.int(labelType)
			w.bytesValue(3, []byte(ManifestType))
			w.int(labelAlg)
			w.int(algEdDSA)
			w.int(labelKeyID)
			w.bytesValue(2, kid[:])
		}), []byte{0xa0}),
		"short key id": envelope(header(func(w *writer) {
			w.head(5, 3)
			w.int(labelAlg)
			w.int(algEdDSA)
			w.int(labelType)
			w.bytesValue(3, []byte(ManifestType))
			w.int(labelKeyID)
			w.bytesValue(2, kid[:31])
		}), []byte{0xa0}),
		"non-shortest length": func() []byte {
			if good[2] != 0x58 {
				t.Fatalf("protected header length is encoded as %#x", good[2])
			}
			return append([]byte{good[0], good[1], 0x59, 0x00, good[3]}, good[4:]...)
		}(),
	}
	for name, data := range cases {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: accepted %s", name, hex.EncodeToString(data))
		}
	}
	if _, err := Parse(envelope(protectedHeader(ManifestType, kid), []byte{0xa0})); err != nil {
		t.Fatalf("control envelope rejected: %v", err)
	}
}

func TestKeyIDIsSPKIDigest(t *testing.T) {
	pub, _ := newKey(t)
	spki := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, pub...)
	if got, direct := KeyIDOf(pub), KeyID(sha256.Sum256(spki)); got != direct {
		t.Fatalf("key id %x is not the SPKI digest %x", got, direct)
	}
}

func FuzzParse(f *testing.F) {
	_, priv := newKey(f)
	f.Add(Sign(priv, ManifestType, []byte("m"), true))
	f.Add(Sign(priv, DelegationType, []byte{0xa0}, false))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(data)
		if err != nil {
			return
		}
		if len(s.Signature) != ed25519.SignatureSize {
			t.Fatal("accepted a short signature")
		}
	})
}
