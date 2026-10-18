package image

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/trust"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

var now = time.Unix(1_800_000_000, 0)

func buildBundle(t *testing.T) (string, *trust.Store, *bundle.Verified) {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	leafPub, leafPriv, _ := ed25519.GenerateKey(rand.Reader)
	certs := cose.Sign(rootPriv, cose.DelegationType, trust.EncodeDelegation(&trust.Delegation{
		Key: leafPub, Epoch: 1, NotBefore: 0, NotAfter: 1 << 40, Purposes: []string{trust.PurposeRelease},
	}), false)
	payload := t.TempDir()
	os.MkdirAll(filepath.Join(payload, "Images/amd64"), 0o755)
	os.WriteFile(filepath.Join(payload, "Images/amd64/main"), []byte("#!/bin/sh\necho packed\n"), 0o755)
	big := make([]byte, 300000)
	rand.Read(big)
	os.MkdirAll(filepath.Join(payload, "Resources"), 0o755)
	os.WriteFile(filepath.Join(payload, "Resources/data.bin"), big, 0o644)
	out := filepath.Join(t.TempDir(), "Packed.sxi")
	t.Cleanup(func() { bundle.Unseal(out) })
	v, err := bundle.Build(payload, out, bundle.Spec{
		ApplicationID: "dev.sinty.packed", DisplayName: "Packed", ReleaseVersion: "1", ReleaseSequence: 1,
		EntryPoints: []wire.EntryPoint{{Architecture: wire.AMD64, ImagePath: "Images/amd64/main", Personality: wire.Linux}},
		State:       wire.StatePolicy{Current: 1, MinimumReadable: 1, MaximumReadable: 1},
	}, bundle.Signing{Root: rootPub, Leaf: leafPriv, Certs: certs}, now)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := trust.Open([]trust.Root{{Name: "test", Key: rootPub}}, "")
	return out, store, v
}

func TestPackIsReproducibleAndExtractsToTheSameSlot(t *testing.T) {
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		t.Skip("erofs-utils is not installed")
	}
	dir, store, verified := buildBundle(t)
	work := t.TempDir()
	first, err := Pack(dir, filepath.Join(work, "a.sxi"), verified.SlotID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Pack(dir, filepath.Join(work, "b.sxi"), verified.SlotID)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 != second.SHA256 || first.Verity.RootHash != second.Verity.RootHash {
		t.Fatal("packing the same bundle twice gave different images")
	}
	if first.Size%BlockSize != 0 {
		t.Fatalf("image size %d is not block aligned", first.Size)
	}
	extracted := filepath.Join(work, "extracted")
	t.Cleanup(func() { bundle.Unseal(extracted) })
	if err := Extract(first.Path, extracted); err != nil {
		t.Fatal(err)
	}
	again, err := bundle.Verify(extracted, store, now)
	if err != nil {
		t.Fatal(err)
	}
	if again.SlotID != verified.SlotID {
		t.Fatal("the image holds a different slot")
	}
}
