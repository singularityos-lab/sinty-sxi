package trust

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

var (
	ErrUnknownPublisher = errors.New("trust: publisher root is not in the trust store")
	ErrPurpose          = errors.New("trust: signer is not delegated for this purpose")
	ErrExpired          = errors.New("trust: delegation is not valid at this time")
	ErrStaleDelegation  = errors.New("trust: delegation epoch is stale")
	ErrStaleRevocation  = errors.New("trust: revocation epoch is stale")
	ErrRevokedSigner    = errors.New("trust: signer is revoked")
	ErrReleaseFloor     = errors.New("trust: release sequence is below the accepted floor")
)

type Root struct {
	Name string
	Key  ed25519.PublicKey
}

func (r Root) KeyID() cose.KeyID {
	return cose.KeyIDOf(r.Key)
}

func (r Root) Identity() [wire.DigestSize]byte {
	return wire.PublisherIdentity([wire.DigestSize]byte(r.KeyID()))
}

type history struct {
	DelegationEpoch        uint64            `json:"delegation_epoch"`
	RevocationEpoch        uint64            `json:"revocation_epoch"`
	MinimumDelegationEpoch uint64            `json:"minimum_delegation_epoch"`
	Revoked                []string          `json:"revoked,omitempty"`
	Sequences              map[string]uint64 `json:"sequences,omitempty"`
}

type Store struct {
	mu      sync.Mutex
	roots   map[cose.KeyID]Root
	history map[string]*history
	path    string
}

type Signer struct {
	Root       Root
	Key        ed25519.PublicKey
	Delegation *Delegation
}

func LoadRoots(dir string) ([]Root, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var roots []Root
	for _, name := range names {
		key, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trust: %s is not a raw Ed25519 public key", name)
		}
		roots = append(roots, Root{Name: strings.TrimSuffix(filepath.Base(name), ".pub"), Key: ed25519.PublicKey(key)})
	}
	return roots, nil
}

func Open(roots []Root, statePath string) (*Store, error) {
	s := &Store{roots: map[cose.KeyID]Root{}, history: map[string]*history{}, path: statePath}
	for _, r := range roots {
		s.roots[r.KeyID()] = r
	}
	if statePath == "" {
		return s, nil
	}
	data, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.history); err != nil {
		return nil, fmt.Errorf("trust: %s: %w", statePath, err)
	}
	return s, nil
}

func (s *Store) Root(id cose.KeyID) (Root, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roots[id]
	if !ok {
		return Root{}, ErrUnknownPublisher
	}
	return r, nil
}

func (s *Store) entry(r Root) *history {
	id := r.KeyID()
	key := hex.EncodeToString(id[:])
	h := s.history[key]
	if h == nil {
		h = &history{}
		s.history[key] = h
	}
	return h
}

func (h *history) revoked(id cose.KeyID) bool {
	want := hex.EncodeToString(id[:])
	for _, k := range h.Revoked {
		if k == want {
			return true
		}
	}
	return false
}

func (s *Store) Signer(rootID cose.KeyID, certs []byte, purpose string, now time.Time) (*Signer, error) {
	root, err := s.Root(rootID)
	if err != nil {
		return nil, err
	}
	envelope, err := cose.Parse(certs)
	if err != nil {
		return nil, err
	}
	payload, err := envelope.Verify(root.Key, cose.DelegationType, nil)
	if err != nil {
		return nil, err
	}
	d, err := ParseDelegation(payload)
	if err != nil {
		return nil, err
	}
	if !d.Allows(purpose) {
		return nil, ErrPurpose
	}
	unix := uint64(now.Unix())
	if unix < d.NotBefore || unix >= d.NotAfter {
		return nil, ErrExpired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.entry(root)
	if d.Epoch < h.MinimumDelegationEpoch || d.Epoch < h.DelegationEpoch {
		return nil, ErrStaleDelegation
	}
	if h.revoked(cose.KeyIDOf(d.Key)) {
		return nil, ErrRevokedSigner
	}
	return &Signer{Root: root, Key: d.Key, Delegation: d}, nil
}

func (s *Store) CheckRelease(signer *Signer, m *wire.Manifest) error {
	if cose.KeyID(m.Publisher.RootKeyID) != signer.Root.KeyID() || cose.KeyID(m.Publisher.LeafKeyID) != cose.KeyIDOf(signer.Key) {
		return ErrUnknownPublisher
	}
	if m.Publisher.DelegationEpoch != signer.Delegation.Epoch {
		return ErrStaleDelegation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.entry(signer.Root)
	if m.Publisher.RevocationEpoch < h.RevocationEpoch {
		return ErrStaleRevocation
	}
	if m.ReleaseSequence < h.Sequences[m.ApplicationID] {
		return ErrReleaseFloor
	}
	return nil
}

func (s *Store) Accept(signer *Signer, m *wire.Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.entry(signer.Root)
	if signer.Delegation.Epoch > h.DelegationEpoch {
		h.DelegationEpoch = signer.Delegation.Epoch
	}
	if m != nil {
		if h.Sequences == nil {
			h.Sequences = map[string]uint64{}
		}
		if m.ReleaseSequence > h.Sequences[m.ApplicationID] {
			h.Sequences[m.ApplicationID] = m.ReleaseSequence
		}
	}
	return s.save()
}

func (s *Store) ApplyRevocation(rootID cose.KeyID, statement []byte) error {
	root, err := s.Root(rootID)
	if err != nil {
		return err
	}
	envelope, err := cose.Parse(statement)
	if err != nil {
		return err
	}
	payload, err := envelope.Verify(root.Key, cose.RevocationType, nil)
	if err != nil {
		return err
	}
	r, err := ParseRevocation(payload)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.entry(root)
	if r.Epoch < h.RevocationEpoch {
		return ErrStaleRevocation
	}
	if r.Epoch == h.RevocationEpoch && r.Epoch != 0 {
		return nil
	}
	h.RevocationEpoch = r.Epoch
	if r.MinimumDelegationEpoch > h.MinimumDelegationEpoch {
		h.MinimumDelegationEpoch = r.MinimumDelegationEpoch
	}
	for _, k := range r.RevokedKeys {
		if !h.revoked(k) {
			h.Revoked = append(h.Revoked, hex.EncodeToString(k[:]))
		}
	}
	sort.Strings(h.Revoked)
	return s.save()
}

func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.history, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".trust-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
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
	return os.Rename(tmp.Name(), s.path)
}
