package index

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/trust"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

const (
	Schema   = 1
	MaxBytes = 4 << 20
)

var (
	ErrSchema   = errors.New("index: unsupported schema")
	ErrRollback = errors.New("index: older than an index already seen")
	ErrInvalid  = errors.New("index: invalid entry")
)

type Release struct {
	Version  string `json:"version"`
	Sequence uint64 `json:"sequence"`
	URL      string `json:"url"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Verity   string `json:"verity"`
	Slot     string `json:"slot"`
	Arch     string `json:"arch"`
}

type App struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Summary     string    `json:"summary,omitempty"`
	Description string    `json:"description,omitempty"`
	Icon        string    `json:"icon,omitempty"`
	Categories  []string  `json:"categories,omitempty"`
	Collections []string  `json:"collections,omitempty"`
	Homepage    string    `json:"homepage,omitempty"`
	License     string    `json:"license,omitempty"`
	Releases    []Release `json:"releases"`
}

type Index struct {
	Schema    int    `json:"schema"`
	Root      string `json:"root"`
	Name      string `json:"name"`
	Sequence  uint64 `json:"sequence"`
	Generated string `json:"generated"`
	Apps      []App  `json:"apps"`
}

type Signed struct {
	Index  *Index
	Signer *trust.Signer
	Bytes  []byte
}

func digestOK(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == wire.DigestSize
}

func (ix *Index) Validate() error {
	if ix.Schema != Schema {
		return ErrSchema
	}
	if !digestOK(ix.Root) || ix.Sequence == 0 || ix.Name == "" {
		return fmt.Errorf("%w: header", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, app := range ix.Apps {
		if seen[app.ID] {
			return fmt.Errorf("%w: %s listed twice", ErrInvalid, app.ID)
		}
		seen[app.ID] = true
		if app.Name == "" || len(app.Releases) == 0 {
			return fmt.Errorf("%w: %s", ErrInvalid, app.ID)
		}
		for _, r := range app.Releases {
			if r.Sequence == 0 || r.Size <= 0 || r.URL == "" || !digestOK(r.SHA256) || !digestOK(r.Verity) || !digestOK(r.Slot) {
				return fmt.Errorf("%w: %s release %d", ErrInvalid, app.ID, r.Sequence)
			}
			if r.Arch != "amd64" && r.Arch != "arm64" {
				return fmt.Errorf("%w: %s architecture %q", ErrInvalid, app.ID, r.Arch)
			}
		}
	}
	return nil
}

func Encode(ix *Index) ([]byte, error) {
	sort.Slice(ix.Apps, func(a, b int) bool { return ix.Apps[a].ID < ix.Apps[b].ID })
	for i := range ix.Apps {
		r := ix.Apps[i].Releases
		sort.Slice(r, func(a, b int) bool { return r[a].Sequence > r[b].Sequence })
	}
	if err := ix.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ix); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Verify(data, signature, certs []byte, store *trust.Store, now time.Time, lastSequence uint64) (*Signed, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%w: too large", ErrInvalid)
	}
	envelope, err := cose.Parse(signature)
	if err != nil {
		return nil, err
	}
	var header struct {
		Root string `json:"root"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	raw, err := hex.DecodeString(header.Root)
	if err != nil || len(raw) != wire.DigestSize {
		return nil, fmt.Errorf("%w: root", ErrInvalid)
	}
	var rootID cose.KeyID
	copy(rootID[:], raw)
	signer, err := store.Signer(rootID, certs, trust.PurposeIndex, now)
	if err != nil {
		return nil, err
	}
	if _, err := envelope.Verify(signer.Key, cose.IndexType, data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var ix Index
	if err := dec.Decode(&ix); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := ix.Validate(); err != nil {
		return nil, err
	}
	if ix.Sequence < lastSequence {
		return nil, ErrRollback
	}
	return &Signed{Index: &ix, Signer: signer, Bytes: data}, nil
}

func (ix *Index) Find(id string) *App {
	for i := range ix.Apps {
		if ix.Apps[i].ID == id {
			return &ix.Apps[i]
		}
	}
	return nil
}

func (a *App) Latest(arch string) *Release {
	var best *Release
	for i := range a.Releases {
		r := &a.Releases[i]
		if r.Arch == arch && (best == nil || r.Sequence > best.Sequence) {
			best = r
		}
	}
	return best
}

func Decode32(value string) [wire.DigestSize]byte {
	var out [wire.DigestSize]byte
	raw, _ := hex.DecodeString(value)
	copy(out[:], raw)
	return out
}
