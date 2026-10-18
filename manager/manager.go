package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/image"
	"github.com/singularityos-lab/sinty-sxi/index"
	"github.com/singularityos-lab/sinty-sxi/trust"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

var (
	ErrUnknownApp   = errors.New("sxi: the application is not in any collection")
	ErrNoRelease    = errors.New("sxi: no release for this architecture")
	ErrUpToDate     = errors.New("sxi: the newest release is already installed")
	ErrNotInstalled = errors.New("sxi: the application is not installed")
	ErrNoPrevious   = errors.New("sxi: there is no previous release to go back to")
	ErrMismatch     = errors.New("sxi: the download does not match the collection")
)

type Source struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Mounter interface {
	Mount(imagePath, hashPath string, rootHash [32]byte, name, target string, exec bool) error
	Release(name, target string, backing ...string) error
}

type kernel struct{}

func (kernel) Mount(imagePath, hashPath string, rootHash [32]byte, name, target string, exec bool) error {
	_, err := image.Mount(imagePath, hashPath, rootHash, name, target, exec)
	return err
}

func (kernel) Release(name, target string, backing ...string) error {
	return image.Release(name, target, backing...)
}

type Config struct {
	Roots   string
	State   string
	Run     string
	Sources []Source
	Arch    string
	Client  *http.Client
	Mounter Mounter
	Now     func() time.Time
}

type Progress func(stage string, done, total int64)

type Available struct {
	index.App
	Source    string `json:"source"`
	Installed *Slot  `json:"installed,omitempty"`
}

type Manager struct {
	cfg     Config
	mu      sync.Mutex
	store   *trust.Store
	reg     *registry
	indexes map[string]*index.Signed
}

func New(cfg Config) (*Manager, error) {
	if cfg.Arch == "" {
		cfg.Arch = runtime.GOARCH
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if cfg.Mounter == nil {
		cfg.Mounter = kernel{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	roots, err := trust.LoadRoots(cfg.Roots)
	if err != nil {
		return nil, err
	}
	store, err := trust.Open(roots, filepath.Join(cfg.State, "trust.json"))
	if err != nil {
		return nil, err
	}
	reg, err := loadRegistry(filepath.Join(cfg.State, "registry.json"))
	if err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg, store: store, reg: reg, indexes: map[string]*index.Signed{}}
	for _, src := range cfg.Sources {
		if signed, err := m.loadCached(src); err == nil {
			m.indexes[src.Name] = signed
		}
	}
	return m, nil
}

func (m *Manager) imagePath(slot string) string {
	return filepath.Join(m.cfg.State, "images", slot+".sxi")
}

func (m *Manager) hashPath(slot string) string {
	return filepath.Join(m.cfg.State, "images", slot+".verity")
}

func (m *Manager) appMount(id string) string {
	return filepath.Join(m.cfg.Run, "apps", id)
}

func mapName(slot string) string {
	return "sxi-" + slot[:32]
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, app := range m.reg.list() {
		if err := m.activate(&app); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", app.ID, err))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) activate(app *Installed) error {
	slot := app.Active.Slot
	m.cfg.Mounter.Release(mapName(slot), m.appMount(app.ID), m.imagePath(slot), m.hashPath(slot))
	if err := m.cfg.Mounter.Mount(m.imagePath(slot), m.hashPath(slot), index.Decode32(app.Active.Verity), mapName(slot), m.appMount(app.ID), true); err != nil {
		return err
	}
	return m.export(app)
}

func (m *Manager) deactivate(app *Installed) {
	m.unexport(app.ID)
	slot := app.Active.Slot
	m.cfg.Mounter.Release(mapName(slot), m.appMount(app.ID), m.imagePath(slot), m.hashPath(slot))
	os.Remove(m.appMount(app.ID))
}

func (m *Manager) cacheDir(src Source) string {
	return filepath.Join(m.cfg.State, "indexes", src.Name)
}

func (m *Manager) loadCached(src Source) (*index.Signed, error) {
	dir := m.cacheDir(src)
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	signature, err := os.ReadFile(filepath.Join(dir, "index.json.cose"))
	if err != nil {
		return nil, err
	}
	certs, err := os.ReadFile(filepath.Join(dir, "index.certs"))
	if err != nil {
		return nil, err
	}
	return index.Verify(data, signature, certs, m.store, m.cfg.Now(), 0)
}

func (m *Manager) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sxi: %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("sxi: %s is larger than %d bytes", url, limit)
	}
	return data, nil
}

func (m *Manager) Refresh(ctx context.Context) error {
	var errs []error
	for _, src := range m.cfg.Sources {
		if err := m.refresh(ctx, src); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) refresh(ctx context.Context, src Source) error {
	data, err := m.get(ctx, src.URL+"/index.json", index.MaxBytes)
	if err != nil {
		return err
	}
	signature, err := m.get(ctx, src.URL+"/index.json.cose", 65536)
	if err != nil {
		return err
	}
	certs, err := m.get(ctx, src.URL+"/index.certs", 65536)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	signed, err := index.Verify(data, signature, certs, m.store, m.cfg.Now(), m.reg.Seen[src.Name])
	if err != nil {
		return err
	}
	dir := m.cacheDir(src)
	for name, content := range map[string][]byte{"index.json": data, "index.json.cose": signature, "index.certs": certs} {
		if err := writeAtomic(filepath.Join(dir, name), content, 0o644); err != nil {
			return err
		}
	}
	m.indexes[src.Name] = signed
	if signed.Index.Sequence > m.reg.Seen[src.Name] {
		m.reg.Seen[src.Name] = signed.Index.Sequence
		return m.reg.save()
	}
	return nil
}

func (m *Manager) Available() []Available {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Available
	names := make([]string, 0, len(m.indexes))
	for name := range m.indexes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, app := range m.indexes[name].Index.Apps {
			a := Available{App: app, Source: name}
			if inst := m.reg.Apps[app.ID]; inst != nil && inst.Source == name {
				slot := inst.Active
				a.Installed = &slot
			}
			out = append(out, a)
		}
	}
	return out
}

func (m *Manager) Installed() []Installed {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reg.list()
}

func (m *Manager) find(id string) (string, *index.App) {
	names := make([]string, 0, len(m.indexes))
	for name := range m.indexes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if app := m.indexes[name].Index.Find(id); app != nil {
			return name, app
		}
	}
	return "", nil
}

func (m *Manager) download(ctx context.Context, r *index.Release, dest string, progress Progress) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return err
	}
	resp, err := m.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sxi: %s: %s", r.URL, resp.Status)
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	var done int64
	buf := make([]byte, 1<<20)
	body := io.LimitReader(resp.Body, r.Size+1)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			done += int64(n)
			if done > r.Size {
				return fmt.Errorf("%w: the image is larger than listed", ErrMismatch)
			}
			h.Write(buf[:n])
			if _, err := f.Write(buf[:n]); err != nil {
				return err
			}
			if progress != nil {
				progress("download", done, r.Size)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if done != r.Size || hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		return fmt.Errorf("%w: size or digest", ErrMismatch)
	}
	return f.Sync()
}

func (m *Manager) Install(ctx context.Context, id string, progress Progress) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	source, app := m.find(id)
	if app == nil {
		return ErrUnknownApp
	}
	release := app.Latest(m.cfg.Arch)
	if release == nil {
		return ErrNoRelease
	}
	current := m.reg.Apps[id]
	if current != nil && current.Active.Sequence >= release.Sequence {
		return ErrUpToDate
	}
	staging := filepath.Join(m.cfg.State, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(m.cfg.State, "images"), 0o755); err != nil {
		return err
	}
	stagedImage := filepath.Join(staging, release.Slot+".sxi")
	stagedHash := filepath.Join(staging, release.Slot+".verity")
	os.Remove(stagedImage)
	os.Remove(stagedHash)
	defer os.Remove(stagedImage)
	defer os.Remove(stagedHash)
	if err := m.download(ctx, release, stagedImage, progress); err != nil {
		return err
	}
	if progress != nil {
		progress("verify", 0, 1)
	}
	slot := index.Decode32(release.Slot)
	salt, uuid := image.SaltFor(slot)
	packed, err := image.Describe(stagedImage, salt, uuid)
	if err != nil {
		return err
	}
	if hex.EncodeToString(packed.Verity.RootHash[:]) != release.Verity {
		return fmt.Errorf("%w: verity root hash", ErrMismatch)
	}
	if err := writeAtomic(stagedHash, packed.Verity.Tree, 0o644); err != nil {
		return err
	}
	stageMount := filepath.Join(m.cfg.Run, "staging", release.Slot[:32])
	stageName := "sxi-stage-" + release.Slot[:24]
	if err := m.cfg.Mounter.Mount(stagedImage, stagedHash, packed.Verity.RootHash, stageName, stageMount, false); err != nil {
		return err
	}
	verified, verr := bundle.Verify(stageMount, m.store, m.cfg.Now())
	m.cfg.Mounter.Release(stageName, stageMount, stagedImage, stagedHash)
	os.Remove(stageMount)
	if verr != nil {
		return verr
	}
	man := verified.Manifest
	if verified.SlotID != slot || man.ApplicationID != id || man.ReleaseSequence != release.Sequence {
		return fmt.Errorf("%w: the image holds another release", ErrMismatch)
	}
	if !hasEntry(man, m.cfg.Arch) {
		return ErrNoRelease
	}
	if err := os.Rename(stagedImage, m.imagePath(release.Slot)); err != nil {
		return err
	}
	if err := os.Rename(stagedHash, m.hashPath(release.Slot)); err != nil {
		return err
	}
	if err := m.store.Accept(verified.Signer, man); err != nil {
		return err
	}
	next := &Installed{
		ID:        id,
		Name:      man.DisplayName,
		Publisher: hex.EncodeToString(man.PublisherIdentity[:]),
		Source:    source,
		Active:    Slot{Version: man.ReleaseVersion, Sequence: man.ReleaseSequence, Slot: release.Slot, Verity: release.Verity, SHA256: release.SHA256},
		Installed: m.cfg.Now().UTC().Format(time.RFC3339),
	}
	if current != nil {
		previous := current.Active
		next.Previous = &previous
		m.deactivate(current)
		if current.Previous != nil && current.Previous.Slot != release.Slot {
			os.Remove(m.imagePath(current.Previous.Slot))
			os.Remove(m.hashPath(current.Previous.Slot))
		}
	}
	m.reg.Apps[id] = next
	if err := m.reg.save(); err != nil {
		return err
	}
	if progress != nil {
		progress("activate", 1, 1)
	}
	return m.activate(next)
}

func hasEntry(man *wire.Manifest, arch string) bool {
	want := map[string]wire.Architecture{"amd64": wire.AMD64, "arm64": wire.ARM64}[arch]
	for _, e := range man.EntryPoints {
		if e.Architecture == want && e.Personality == wire.Linux {
			return true
		}
	}
	return false
}

func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	app := m.reg.Apps[id]
	if app == nil {
		return ErrNotInstalled
	}
	m.deactivate(app)
	delete(m.reg.Apps, id)
	if err := m.reg.save(); err != nil {
		return err
	}
	for _, slot := range []*Slot{&app.Active, app.Previous} {
		if slot != nil {
			os.Remove(m.imagePath(slot.Slot))
			os.Remove(m.hashPath(slot.Slot))
		}
	}
	return nil
}

func (m *Manager) Rollback(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	app := m.reg.Apps[id]
	if app == nil {
		return ErrNotInstalled
	}
	if app.Previous == nil {
		return ErrNoPrevious
	}
	m.deactivate(app)
	current := app.Active
	app.Active, app.Previous = *app.Previous, &current
	if err := m.reg.save(); err != nil {
		return err
	}
	return m.activate(app)
}

func (m *Manager) MarshalState() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return json.Marshal(m.reg.list())
}
