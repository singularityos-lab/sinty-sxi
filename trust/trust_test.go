package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

var now = time.Unix(1_800_000_000, 0)

type publisher struct {
	root     ed25519.PrivateKey
	leaf     ed25519.PrivateKey
	rootInfo Root
}

func newPublisher(t *testing.T) *publisher {
	t.Helper()
	rootPub, root, _ := ed25519.GenerateKey(rand.Reader)
	_, leaf, _ := ed25519.GenerateKey(rand.Reader)
	return &publisher{root: root, leaf: leaf, rootInfo: Root{Name: "test", Key: rootPub}}
}

func (p *publisher) certs(epoch uint64, purposes ...string) []byte {
	d := &Delegation{
		Key:       p.leaf.Public().(ed25519.PublicKey),
		Epoch:     epoch,
		NotBefore: uint64(now.Add(-time.Hour).Unix()),
		NotAfter:  uint64(now.Add(time.Hour).Unix()),
		Purposes:  purposes,
	}
	return cose.Sign(p.root, cose.DelegationType, EncodeDelegation(d), false)
}

func (p *publisher) manifest(epoch, revocation, sequence uint64) *wire.Manifest {
	return &wire.Manifest{
		ApplicationID:   "dev.sinty.test",
		ReleaseSequence: sequence,
		Publisher: wire.Publisher{
			RootKeyID:       [wire.DigestSize]byte(p.rootInfo.KeyID()),
			LeafKeyID:       [wire.DigestSize]byte(cose.KeyIDOf(p.leaf.Public().(ed25519.PublicKey))),
			DelegationEpoch: epoch,
			RevocationEpoch: revocation,
		},
	}
}

func TestDelegationRoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	d := &Delegation{Key: pub, Epoch: 3, NotBefore: 10, NotAfter: 20, Purposes: []string{PurposeRelease, PurposeIndex}}
	got, err := ParseDelegation(EncodeDelegation(d))
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 3 || !got.Allows(PurposeIndex) || !got.Allows(PurposeRelease) || got.Allows("other") {
		t.Fatalf("delegation = %+v", got)
	}
	data := EncodeDelegation(d)
	if _, err := ParseDelegation(append(data, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := ParseDelegation(EncodeDelegation(&Delegation{Key: pub, NotBefore: 5, NotAfter: 5, Purposes: []string{PurposeRelease}})); err == nil {
		t.Fatal("empty validity window accepted")
	}
}

func TestSignerChain(t *testing.T) {
	p := newPublisher(t)
	store, err := Open([]Root{p.rootInfo}, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := store.Signer(p.rootInfo.KeyID(), p.certs(1, PurposeRelease), PurposeRelease, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckRelease(signer, p.manifest(1, 0, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Signer(p.rootInfo.KeyID(), p.certs(1, PurposeRelease), PurposeIndex, now); !errors.Is(err, ErrPurpose) {
		t.Fatalf("index purpose: %v", err)
	}
	if _, err := store.Signer(p.rootInfo.KeyID(), p.certs(1, PurposeRelease), PurposeRelease, now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	selfSigned := cose.Sign(p.leaf, cose.DelegationType, EncodeDelegation(&Delegation{
		Key: p.leaf.Public().(ed25519.PublicKey), Epoch: 9, NotBefore: 0, NotAfter: 1 << 40, Purposes: []string{PurposeRelease},
	}), false)
	if _, err := store.Signer(p.rootInfo.KeyID(), selfSigned, PurposeRelease, now); err == nil {
		t.Fatal("a leaf delegated itself")
	}
	other := newPublisher(t)
	if _, err := store.Signer(other.rootInfo.KeyID(), other.certs(1, PurposeRelease), PurposeRelease, now); !errors.Is(err, ErrUnknownPublisher) {
		t.Fatalf("unknown root: %v", err)
	}
}

func TestEpochsAndFloors(t *testing.T) {
	p := newPublisher(t)
	state := filepath.Join(t.TempDir(), "trust.json")
	store, _ := Open([]Root{p.rootInfo}, state)
	signer, err := store.Signer(p.rootInfo.KeyID(), p.certs(2, PurposeRelease), PurposeRelease, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(signer, p.manifest(2, 0, 5)); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open([]Root{p.rootInfo}, state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Signer(p.rootInfo.KeyID(), p.certs(1, PurposeRelease), PurposeRelease, now); !errors.Is(err, ErrStaleDelegation) {
		t.Fatalf("older delegation after reload: %v", err)
	}
	signer, err = reopened.Signer(p.rootInfo.KeyID(), p.certs(2, PurposeRelease), PurposeRelease, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.CheckRelease(signer, p.manifest(2, 0, 4)); !errors.Is(err, ErrReleaseFloor) {
		t.Fatalf("rollback: %v", err)
	}
	if err := reopened.CheckRelease(signer, p.manifest(1, 0, 6)); !errors.Is(err, ErrStaleDelegation) {
		t.Fatalf("manifest epoch mismatch: %v", err)
	}
	if err := reopened.CheckRelease(signer, p.manifest(2, 0, 5)); err != nil {
		t.Fatalf("same release again: %v", err)
	}
}

func TestRevocation(t *testing.T) {
	p := newPublisher(t)
	store, _ := Open([]Root{p.rootInfo}, filepath.Join(t.TempDir(), "trust.json"))
	leafID := cose.KeyIDOf(p.leaf.Public().(ed25519.PublicKey))
	statement := func(signer ed25519.PrivateKey, epoch uint64, keys ...cose.KeyID) []byte {
		return cose.Sign(signer, cose.RevocationType, EncodeRevocation(&Revocation{Epoch: epoch, RevokedKeys: keys}), false)
	}
	if err := store.ApplyRevocation(p.rootInfo.KeyID(), statement(p.leaf, 1, leafID)); err == nil {
		t.Fatal("a leaf signed a revocation")
	}
	if err := store.ApplyRevocation(p.rootInfo.KeyID(), statement(p.root, 3, leafID)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Signer(p.rootInfo.KeyID(), p.certs(1, PurposeRelease), PurposeRelease, now); !errors.Is(err, ErrRevokedSigner) {
		t.Fatalf("revoked leaf: %v", err)
	}
	if err := store.ApplyRevocation(p.rootInfo.KeyID(), statement(p.root, 2)); !errors.Is(err, ErrStaleRevocation) {
		t.Fatalf("older revocation: %v", err)
	}
	_, fresh, _ := ed25519.GenerateKey(rand.Reader)
	p.leaf = fresh
	signer, err := store.Signer(p.rootInfo.KeyID(), p.certs(1, PurposeRelease), PurposeRelease, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckRelease(signer, p.manifest(1, 2, 1)); !errors.Is(err, ErrStaleRevocation) {
		t.Fatalf("manifest signed before the revocation: %v", err)
	}
	if err := store.CheckRelease(signer, p.manifest(1, 3, 1)); err != nil {
		t.Fatal(err)
	}
}
