package manager

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

type Slot struct {
	Version  string `json:"version"`
	Sequence uint64 `json:"sequence"`
	Slot     string `json:"slot"`
	Verity   string `json:"verity"`
	SHA256   string `json:"sha256"`
}

type Installed struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	Source    string `json:"source"`
	Active    Slot   `json:"active"`
	Previous  *Slot  `json:"previous,omitempty"`
	Installed string `json:"installed"`
}

type registry struct {
	path string
	Apps map[string]*Installed `json:"apps"`
	Seen map[string]uint64     `json:"index_sequences"`
}

func loadRegistry(path string) (*registry, error) {
	r := &registry{path: path, Apps: map[string]*Installed{}, Seen: map[string]uint64{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, r); err != nil {
		return nil, err
	}
	if r.Apps == nil {
		r.Apps = map[string]*Installed{}
	}
	if r.Seen == nil {
		r.Seen = map[string]uint64{}
	}
	return r, nil
}

func (r *registry) list() []Installed {
	out := make([]Installed, 0, len(r.Apps))
	for _, app := range r.Apps {
		out = append(out, *app)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (r *registry) save() error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(r.path, append(data, '\n'), 0o644)
}
