package index

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/trust"
)

var now = time.Unix(1_800_000_000, 0)

func digest(b byte) string {
	return strings.Repeat(hex.EncodeToString([]byte{b}), 32)
}

func setup(t *testing.T, purposes ...string) (*trust.Store, ed25519.PrivateKey, []byte, *Index) {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	leafPub, leafPriv, _ := ed25519.GenerateKey(rand.Reader)
	certs := cose.Sign(rootPriv, cose.DelegationType, trust.EncodeDelegation(&trust.Delegation{
		Key: leafPub, Epoch: 1, NotBefore: 0, NotAfter: 1 << 40, Purposes: purposes,
	}), false)
	store, _ := trust.Open([]trust.Root{{Name: "test", Key: rootPub}}, "")
	id := cose.KeyIDOf(rootPub)
	ix := &Index{
		Schema: Schema, Root: hex.EncodeToString(id[:]), Name: "Test collection", Sequence: 3,
		Generated: "2027-01-15T00:00:00Z",
		Apps: []App{{ID: "dev.sinty.hello", Name: "Hello", Collections: []string{"essentials"}, Releases: []Release{
			{Version: "1.0", Sequence: 1, URL: "https://example.invalid/hello-1.sxi", Size: 4096, SHA256: digest(1), Verity: digest(2), Slot: digest(3), Arch: "amd64"},
			{Version: "1.1", Sequence: 2, URL: "https://example.invalid/hello-2.sxi", Size: 4096, SHA256: digest(4), Verity: digest(5), Slot: digest(6), Arch: "amd64"},
		}}},
	}
	return store, leafPriv, certs, ix
}

func TestSignedIndex(t *testing.T) {
	store, leaf, certs, ix := setup(t, trust.PurposeIndex)
	data, err := Encode(ix)
	if err != nil {
		t.Fatal(err)
	}
	signature := cose.Sign(leaf, cose.IndexType, data, true)
	signed, err := Verify(data, signature, certs, store, now, 3)
	if err != nil {
		t.Fatal(err)
	}
	if r := signed.Index.Find("dev.sinty.hello").Latest("amd64"); r == nil || r.Sequence != 2 {
		t.Fatalf("latest = %+v", r)
	}
	if _, err := Verify(data, signature, certs, store, now, 4); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback: %v", err)
	}
	tampered := []byte(strings.Replace(string(data), "hello-2.sxi", "evil-2.sxi", 1))
	if _, err := Verify(tampered, signature, certs, store, now, 0); !errors.Is(err, cose.ErrSignature) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestReleaseKeyCannotSignIndex(t *testing.T) {
	store, leaf, certs, ix := setup(t, trust.PurposeRelease)
	data, _ := Encode(ix)
	if _, err := Verify(data, cose.Sign(leaf, cose.IndexType, data, true), certs, store, now, 0); !errors.Is(err, trust.ErrPurpose) {
		t.Fatalf("got %v", err)
	}
}

func TestValidate(t *testing.T) {
	_, _, _, ix := setup(t, trust.PurposeIndex)
	ix.Apps[0].Releases[0].SHA256 = "00"
	if _, err := Encode(ix); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short digest: %v", err)
	}
	_, _, _, ix = setup(t, trust.PurposeIndex)
	ix.Apps = append(ix.Apps, ix.Apps[0])
	if _, err := Encode(ix); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate app: %v", err)
	}
}
