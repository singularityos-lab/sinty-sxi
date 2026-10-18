package manager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/image"
	"github.com/singularityos-lab/sinty-sxi/index"
	"github.com/singularityos-lab/sinty-sxi/trust"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

var now = time.Unix(1_800_000_000, 0)

type publisher struct {
	root     ed25519.PublicKey
	rootKey  ed25519.PrivateKey
	leaf     ed25519.PrivateKey
	certs    []byte
	files    map[string][]byte
	sequence uint64
}

func newPublisher(t *testing.T) *publisher {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	leafPub, leafPriv, _ := ed25519.GenerateKey(rand.Reader)
	certs := cose.Sign(rootPriv, cose.DelegationType, trust.EncodeDelegation(&trust.Delegation{
		Key: leafPub, Epoch: 1, NotBefore: 0, NotAfter: 1 << 40, Purposes: []string{trust.PurposeIndex, trust.PurposeRelease},
	}), false)
	return &publisher{root: rootPub, rootKey: rootPriv, leaf: leafPriv, certs: certs, files: map[string][]byte{}}
}

func (p *publisher) release(t *testing.T, sequence uint64, text string) index.Release {
	t.Helper()
	payload := t.TempDir()
	os.MkdirAll(filepath.Join(payload, "Images/amd64"), 0o755)
	os.MkdirAll(filepath.Join(payload, "Resources"), 0o755)
	os.MkdirAll(filepath.Join(payload, "Icons"), 0o755)
	os.WriteFile(filepath.Join(payload, "Images/amd64/main"), []byte("#!/bin/sh\necho "+text+"\n"), 0o755)
	os.WriteFile(filepath.Join(payload, "Resources/hello.desktop"), []byte("[Desktop Entry]\nType=Application\nName=Hello\nExec=main %U\nIcon=hello\nTryExec=main\n\n[Desktop Action new]\nName=New\nExec=main --new\n"), 0o644)
	os.WriteFile(filepath.Join(payload, "Icons/hello.svg"), []byte("<svg/>"), 0o644)
	dir := filepath.Join(t.TempDir(), "Hello.sxi")
	t.Cleanup(func() { bundle.Unseal(dir) })
	v, err := bundle.Build(payload, dir, bundle.Spec{
		ApplicationID: "dev.sinty.hello", DisplayName: "Hello", ReleaseVersion: fmt.Sprint(sequence), ReleaseSequence: sequence,
		EntryPoints: []wire.EntryPoint{{Architecture: wire.AMD64, ImagePath: "Images/amd64/main", Personality: wire.Linux}},
		Resources:   []string{"Resources/hello.desktop"},
		Icons:       []string{"Icons/hello.svg"},
		State:       wire.StatePolicy{Current: 1, MinimumReadable: 1, MaximumReadable: 1},
	}, bundle.Signing{Root: p.root, Leaf: p.leaf, Certs: p.certs}, now)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "hello.sxi")
	packed, err := image.Pack(dir, out, v.SlotID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	name := fmt.Sprintf("hello-%d.sxi", sequence)
	p.files[name] = data
	return index.Release{
		Version: fmt.Sprint(sequence), Sequence: sequence, URL: "/" + name, Size: packed.Size,
		SHA256: hex.EncodeToString(packed.SHA256[:]), Verity: hex.EncodeToString(packed.Verity.RootHash[:]),
		Slot: hex.EncodeToString(v.SlotID[:]), Arch: "amd64",
	}
}

func (p *publisher) publish(t *testing.T, base string, sequence uint64, releases ...index.Release) {
	t.Helper()
	id := cose.KeyIDOf(p.root)
	for i := range releases {
		if !strings.HasPrefix(releases[i].URL, "http") {
			releases[i].URL = base + releases[i].URL
		}
	}
	data, err := index.Encode(&index.Index{
		Schema: index.Schema, Root: hex.EncodeToString(id[:]), Name: "Test", Sequence: sequence, Generated: "2027-01-01T00:00:00Z",
		Apps: []index.App{{ID: "dev.sinty.hello", Name: "Hello", Releases: releases}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.files["index.json"] = data
	p.files["index.json.cose"] = cose.Sign(p.leaf, cose.IndexType, data, true)
	p.files["index.certs"] = p.certs
}

func setup(t *testing.T) (*Manager, *publisher, *httptest.Server, string) {
	t.Helper()
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		t.Skip("erofs-utils is not installed")
	}
	p := newPublisher(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := p.files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(server.Close)
	base := t.TempDir()
	roots := filepath.Join(base, "roots")
	os.MkdirAll(roots, 0o755)
	os.WriteFile(filepath.Join(roots, "test.pub"), p.root, 0o644)
	run := filepath.Join(base, "run")
	t.Cleanup(func() { bundle.Unseal(run) })
	m, err := New(Config{
		Roots: roots, State: filepath.Join(base, "state"), Run: run,
		Sources: []Source{{Name: "test", URL: server.URL}}, Arch: "amd64",
		Mounter: &ExtractMounter{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, p, server, base
}

func TestInstallUpdateRollbackRemove(t *testing.T) {
	m, p, server, base := setup(t)
	ctx := context.Background()
	first := p.release(t, 1, "one")
	p.publish(t, server.URL, 1, first)
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if apps := m.Available(); len(apps) != 1 || apps[0].ID != "dev.sinty.hello" || apps[0].Installed != nil {
		t.Fatalf("available = %+v", apps)
	}
	var stages []string
	if err := m.Install(ctx, "dev.sinty.hello", func(stage string, done, total int64) { stages = append(stages, stage) }); err != nil {
		t.Fatal(err)
	}
	if len(stages) == 0 || stages[len(stages)-1] != "activate" {
		t.Fatalf("progress = %v", stages)
	}
	mount := filepath.Join(base, "run", "apps", "dev.sinty.hello")
	script, err := os.ReadFile(filepath.Join(mount, "Images/amd64/main"))
	if err != nil || !strings.Contains(string(script), "one") {
		t.Fatalf("mounted entry = %q, %v", script, err)
	}
	desktop, err := os.ReadFile(filepath.Join(base, "run", "share", "applications", "dev.sinty.hello.desktop"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Exec=" + filepath.Join(mount, "Images/amd64/main") + " %U\n",
		"Exec=" + filepath.Join(mount, "Images/amd64/main") + " --new\n",
		"Icon=" + filepath.Join(mount, "Icons/hello.svg") + "\n",
		"X-SXI-Application=dev.sinty.hello\n",
	}
	for _, w := range want {
		if !strings.Contains(string(desktop), w) {
			t.Errorf("desktop file lacks %q:\n%s", w, desktop)
		}
	}
	if strings.Contains(string(desktop), "TryExec") || strings.Contains(string(desktop), "Icon=hello\n") {
		t.Errorf("desktop file kept publisher paths:\n%s", desktop)
	}
	if err := m.Install(ctx, "dev.sinty.hello", nil); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("reinstall: %v", err)
	}

	second := p.release(t, 2, "two")
	p.publish(t, server.URL, 2, first, second)
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Install(ctx, "dev.sinty.hello", nil); err != nil {
		t.Fatal(err)
	}
	script, _ = os.ReadFile(filepath.Join(mount, "Images/amd64/main"))
	if !strings.Contains(string(script), "two") {
		t.Fatalf("after update the entry is %q", script)
	}
	installed := m.Installed()
	if len(installed) != 1 || installed[0].Active.Sequence != 2 || installed[0].Previous == nil || installed[0].Previous.Sequence != 1 {
		t.Fatalf("installed = %+v", installed)
	}
	if err := m.Rollback("dev.sinty.hello"); err != nil {
		t.Fatal(err)
	}
	script, _ = os.ReadFile(filepath.Join(mount, "Images/amd64/main"))
	if !strings.Contains(string(script), "one") {
		t.Fatalf("after rollback the entry is %q", script)
	}

	restarted, err := New(m.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	if apps := restarted.Available(); len(apps) != 1 {
		t.Fatalf("cached index not reloaded: %+v", apps)
	}
	if err := restarted.Remove("dev.sinty.hello"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mount); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mount left behind: %v", err)
	}
	images, _ := filepath.Glob(filepath.Join(base, "state", "images", "*"))
	if len(images) != 0 {
		t.Fatalf("images left behind: %v", images)
	}
}

func TestRejectsBadDownloadsAndOldIndexes(t *testing.T) {
	m, p, server, _ := setup(t)
	ctx := context.Background()
	r := p.release(t, 1, "one")
	good := p.files["hello-1.sxi"]
	p.publish(t, server.URL, 5, r)
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), good...)
	bad[len(bad)/2] ^= 0xff
	p.files["hello-1.sxi"] = bad
	if err := m.Install(ctx, "dev.sinty.hello", nil); !errors.Is(err, ErrMismatch) {
		t.Fatalf("corrupt image: %v", err)
	}
	p.files["hello-1.sxi"] = good
	p.publish(t, server.URL, 4, r)
	if err := m.Refresh(ctx); !errors.Is(err, index.ErrRollback) {
		t.Fatalf("older index: %v", err)
	}
	other := newPublisher(t)
	foreign := other.release(t, 7, "foreign")
	p.files["hello-7.sxi"] = other.files["hello-7.sxi"]
	p.publish(t, server.URL, 6, r, foreign)
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Install(ctx, "dev.sinty.hello", nil); !errors.Is(err, trust.ErrUnknownPublisher) {
		t.Fatalf("image from another publisher: %v", err)
	}
	if len(m.Installed()) != 0 {
		t.Fatal("a rejected image was installed")
	}
}
