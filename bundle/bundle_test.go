package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/trust"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

var now = time.Unix(1_800_000_000, 0)

type fixture struct {
	root  ed25519.PublicKey
	keys  Signing
	store *trust.Store
	dir   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	leafPub, leafPriv, _ := ed25519.GenerateKey(rand.Reader)
	certs := cose.Sign(rootPriv, cose.DelegationType, trust.EncodeDelegation(&trust.Delegation{
		Key: leafPub, Epoch: 1, NotBefore: 0, NotAfter: 1 << 40, Purposes: []string{trust.PurposeRelease},
	}), false)
	store, err := trust.Open([]trust.Root{{Name: "test", Key: rootPub}}, "")
	if err != nil {
		t.Fatal(err)
	}
	payload := t.TempDir()
	write := func(path string, data string, mode os.FileMode) {
		full := filepath.Join(payload, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("Images/amd64/main", "#!/bin/sh\necho hello\n", 0o755)
	write("Resources/app.desktop", "[Desktop Entry]\nName=Test\n", 0o644)
	write("Icons/app.svg", "<svg/>", 0o644)
	out := filepath.Join(t.TempDir(), "Test.sxi")
	t.Cleanup(func() { Unseal(out) })
	spec := Spec{
		ApplicationID:   "dev.sinty.test",
		DisplayName:     "Test",
		ReleaseVersion:  "1.0",
		ReleaseSequence: 1,
		EntryPoints:     []wire.EntryPoint{{Architecture: wire.AMD64, ImagePath: "Images/amd64/main", Personality: wire.Linux}},
		Resources:       []string{"Resources/app.desktop"},
		Icons:           []string{"Icons/app.svg"},
		State:           wire.StatePolicy{Current: 1, MinimumReadable: 1, MaximumReadable: 1},
	}
	keys := Signing{Root: rootPub, Leaf: leafPriv, Certs: certs}
	if _, err := Build(payload, out, spec, keys, now); err != nil {
		t.Fatal(err)
	}
	return &fixture{root: rootPub, keys: keys, store: store, dir: out}
}

func (f *fixture) mutate(t *testing.T, change func(dir string)) error {
	t.Helper()
	if err := Unseal(f.dir); err != nil {
		t.Fatal(err)
	}
	change(f.dir)
	if err := seal(f.dir); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(f.dir, f.store, now)
	return err
}

func TestBuildAndVerify(t *testing.T) {
	f := newFixture(t)
	first, err := Verify(f.dir, f.store, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Verify(f.dir, f.store, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.SlotID != second.SlotID {
		t.Fatal("slot id is not stable")
	}
	if first.Manifest.ApplicationID != "dev.sinty.test" || len(first.Manifest.Inventory) != 7 {
		t.Fatalf("manifest = %+v", first.Manifest)
	}
	if e := first.Manifest.Find("Images/amd64/main"); e == nil || e.Kind != wire.Image || e.Mode != 0o555 {
		t.Fatalf("entry image = %+v", e)
	}
}

func TestRejectsTampering(t *testing.T) {
	cases := map[string]struct {
		change func(t *testing.T, dir string)
		want   error
	}{
		"changed payload": {func(t *testing.T, dir string) {
			p := filepath.Join(dir, "Resources/app.desktop")
			os.Chmod(p, 0o644)
			os.WriteFile(p, []byte("[Desktop Entry]\nName=Evil\n"), 0o644)
			os.Chmod(p, 0o444)
		}, ErrInventory},
		"extra file": {func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, "Resources/extra"), []byte("x"), 0o444)
		}, ErrInventory},
		"symlink": {func(t *testing.T, dir string) {
			os.Symlink("/etc/passwd", filepath.Join(dir, "Resources/link"))
		}, ErrLink},
		"hard link": {func(t *testing.T, dir string) {
			os.Link(filepath.Join(dir, "Icons/app.svg"), filepath.Join(dir, "Icons/copy.svg"))
		}, ErrLink},
		"mode": {func(t *testing.T, dir string) {
			os.Chmod(filepath.Join(dir, "Icons/app.svg"), 0o644)
		}, ErrMode},
		"fifo": {func(t *testing.T, dir string) {
			unix.Mkfifo(filepath.Join(dir, "Resources/pipe"), 0o444)
		}, ErrSpecial},
		"bad name": {func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, "Resources/.six-x"), []byte("x"), 0o444)
		}, ErrName},
		"extra control file": {func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, "SXI/Other"), []byte("x"), 0o444)
		}, ErrControl},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			err := f.mutate(t, func(dir string) { c.change(t, dir) })
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestRejectsForgedSignature(t *testing.T) {
	f := newFixture(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	err := f.mutate(t, func(dir string) {
		p := filepath.Join(dir, ManifestPath)
		manifest, _ := os.ReadFile(p)
		s := filepath.Join(dir, SignaturePath)
		os.Chmod(s, 0o644)
		os.WriteFile(s, cose.Sign(other, cose.ManifestType, manifest, true), 0o444)
		os.Chmod(s, 0o444)
	})
	if !errors.Is(err, cose.ErrKeyID) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsChangedManifest(t *testing.T) {
	f := newFixture(t)
	err := f.mutate(t, func(dir string) {
		p := filepath.Join(dir, ManifestPath)
		manifest, _ := os.ReadFile(p)
		m, err := wire.Decode(manifest)
		if err != nil {
			t.Fatal(err)
		}
		m.DisplayName = "Evil"
		os.Chmod(p, 0o644)
		os.WriteFile(p, wire.Encode(m), 0o444)
		os.Chmod(p, 0o444)
	})
	if !errors.Is(err, cose.ErrSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsUnknownPublisher(t *testing.T) {
	f := newFixture(t)
	empty, _ := trust.Open(nil, "")
	if _, err := Verify(f.dir, empty, now); !errors.Is(err, trust.ErrUnknownPublisher) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsXattr(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.dir, "Icons/app.svg")
	Unseal(f.dir)
	os.Chmod(target, 0o644)
	if err := unix.Setxattr(target, "user.sxi", []byte("x"), 0); err != nil {
		t.Skipf("user xattrs unsupported here: %v", err)
	}
	os.Chmod(target, 0o444)
	seal(f.dir)
	if _, err := Verify(f.dir, f.store, now); !errors.Is(err, ErrMetadata) {
		t.Fatalf("got %v", err)
	}
}
