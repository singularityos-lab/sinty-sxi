package bundle

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/trust"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

const (
	ControlDir     = "SXI"
	ManifestPath   = "SXI/Manifest.cbor"
	SignaturesDir  = "SXI/Signatures"
	SignaturePath  = "SXI/Signatures/Manifest.cose"
	PublisherPath  = "SXI/Signatures/Publisher.certs"
	maxControlFile = 65536
)

var (
	ErrControl   = errors.New("bundle: the SXI control files are missing or unexpected")
	ErrInventory = errors.New("bundle: the tree does not match the signed inventory")
)

type Verified struct {
	Manifest      *wire.Manifest
	ManifestBytes []byte
	Signer        *trust.Signer
	SlotID        [wire.DigestSize]byte
}

func controlLimit(path string) int64 {
	switch path {
	case ManifestPath:
		return wire.ManifestMax
	case SignaturePath, PublisherPath:
		return maxControlFile
	}
	return 0
}

func Verify(dir string, store *trust.Store, now time.Time) (*Verified, error) {
	objects, err := scan(dir, true, controlLimit)
	if err != nil {
		return nil, err
	}
	control := map[string]object{}
	var payload []wire.Entry
	var slot []wire.Entry
	for _, o := range objects {
		slot = append(slot, o.Entry)
		if o.Path == ControlDir || strings.HasPrefix(o.Path, ControlDir+"/") {
			control[o.Path] = o
			continue
		}
		payload = append(payload, o.Entry)
	}
	want := map[string]wire.Kind{
		ControlDir: wire.Directory, ManifestPath: wire.Data, SignaturesDir: wire.Directory,
		SignaturePath: wire.Data, PublisherPath: wire.Data,
	}
	if len(control) != len(want) {
		return nil, ErrControl
	}
	for path, kind := range want {
		if o, ok := control[path]; !ok || o.Kind != kind {
			return nil, fmt.Errorf("%w: %s", ErrControl, path)
		}
	}
	manifestBytes := control[ManifestPath].content
	m, err := wire.Decode(manifestBytes)
	if err != nil {
		return nil, err
	}
	signer, err := store.Signer(cose.KeyID(m.Publisher.RootKeyID), control[PublisherPath].content, trust.PurposeRelease, now)
	if err != nil {
		return nil, err
	}
	signature, err := cose.Parse(control[SignaturePath].content)
	if err != nil {
		return nil, err
	}
	if _, err := signature.Verify(signer.Key, cose.ManifestType, manifestBytes); err != nil {
		return nil, err
	}
	if err := store.CheckRelease(signer, m); err != nil {
		return nil, err
	}
	if len(payload) != len(m.Inventory) {
		return nil, fmt.Errorf("%w: %d objects, %d signed", ErrInventory, len(payload), len(m.Inventory))
	}
	for i := range payload {
		if payload[i] != m.Inventory[i] {
			return nil, fmt.Errorf("%w: %s", ErrInventory, payload[i].Path)
		}
	}
	return &Verified{Manifest: m, ManifestBytes: manifestBytes, Signer: signer, SlotID: wire.SlotID(slot)}, nil
}
