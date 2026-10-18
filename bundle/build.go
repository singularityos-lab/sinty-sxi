package bundle

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/trust"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

type Spec struct {
	ApplicationID   string
	DisplayName     string
	ReleaseVersion  string
	ReleaseSequence uint64
	EntryPoints     []wire.EntryPoint
	Resources       []string
	Icons           []string
	Grants          []string
	Portals         []string
	State           wire.StatePolicy
	Health          wire.HealthPolicy
	RevocationEpoch uint64
}

type Signing struct {
	Root  ed25519.PublicKey
	Leaf  ed25519.PrivateKey
	Certs []byte
}

func Build(payloadDir, outDir string, spec Spec, keys Signing, now time.Time) (*Verified, error) {
	objects, err := scan(payloadDir, false, func(string) int64 { return 0 })
	if err != nil {
		return nil, err
	}
	for _, o := range objects {
		if o.Path == ControlDir || strings.HasPrefix(o.Path, ControlDir+"/") {
			return nil, fmt.Errorf("%w: the payload already has %s", ErrControl, o.Path)
		}
	}
	envelope, err := cose.Parse(keys.Certs)
	if err != nil {
		return nil, err
	}
	payload, err := envelope.Verify(keys.Root, cose.DelegationType, nil)
	if err != nil {
		return nil, err
	}
	delegation, err := trust.ParseDelegation(payload)
	if err != nil {
		return nil, err
	}
	if !delegation.Key.Equal(keys.Leaf.Public()) {
		return nil, errors.New("bundle: the delegation is for a different signing key")
	}
	if err := os.Mkdir(outDir, 0o755); err != nil {
		return nil, err
	}
	inventory := make([]wire.Entry, 0, len(objects))
	for _, o := range objects {
		if err := place(payloadDir, outDir, o.Entry); err != nil {
			return nil, err
		}
		inventory = append(inventory, o.Entry)
	}
	m := &wire.Manifest{
		ApplicationID:   spec.ApplicationID,
		DisplayName:     spec.DisplayName,
		ReleaseVersion:  spec.ReleaseVersion,
		ReleaseSequence: spec.ReleaseSequence,
		PayloadDigest:   wire.PayloadDigestOf(inventory),
		Publisher: wire.Publisher{
			RootKeyID:       [wire.DigestSize]byte(cose.KeyIDOf(keys.Root)),
			LeafKeyID:       [wire.DigestSize]byte(cose.KeyIDOf(keys.Leaf.Public().(ed25519.PublicKey))),
			DelegationEpoch: delegation.Epoch,
			RevocationEpoch: spec.RevocationEpoch,
		},
		EntryPoints: spec.EntryPoints,
		Inventory:   inventory,
		Resources:   sorted(spec.Resources),
		Icons:       sorted(spec.Icons),
		Grants:      sorted(spec.Grants),
		Portals:     sorted(spec.Portals),
		State:       spec.State,
		Health:      spec.Health,
	}
	manifest := wire.Encode(m)
	if _, err := wire.Decode(manifest); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(outDir, SignaturesDir), 0o755); err != nil {
		return nil, err
	}
	files := map[string][]byte{
		ManifestPath:  manifest,
		SignaturePath: cose.Sign(keys.Leaf, cose.ManifestType, manifest, true),
		PublisherPath: keys.Certs,
	}
	for path, data := range files {
		if err := os.WriteFile(filepath.Join(outDir, path), data, 0o444); err != nil {
			return nil, err
		}
	}
	if err := seal(outDir); err != nil {
		return nil, err
	}
	store, err := trust.Open([]trust.Root{{Name: "build", Key: keys.Root}}, "")
	if err != nil {
		return nil, err
	}
	return Verify(outDir, store, now)
}

func sorted(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

func place(src, dst string, e wire.Entry) error {
	target := filepath.Join(dst, e.Path)
	if e.Kind == wire.Directory {
		return os.Mkdir(target, 0o755)
	}
	in, err := os.Open(filepath.Join(src, e.Path))
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(e.Mode))
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(target, os.FileMode(e.Mode))
}

func seal(dir string) error {
	var dirs []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != dir {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	for _, d := range dirs {
		if err := os.Chmod(d, 0o555); err != nil {
			return err
		}
	}
	return nil
}

func Unseal(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return nil
	})
}
