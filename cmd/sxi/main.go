package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/image"
	"github.com/singularityos-lab/sinty-sxi/trust"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

const usage = `usage: sxi <command> [options]

commands:
  keygen    create an Ed25519 key pair (name.key and name.pub)
  delegate  issue a signing key delegation from a publisher root
  revoke    sign a revocation statement with a publisher root
  build     turn a payload directory into a signed bundle
  verify    check a bundle against trusted publisher roots
  pack      write a verified bundle as an erofs image
  inspect   print the manifest of a bundle or a manifest file
  index     create, update and sign a collection index

system commands, through sxid:
  list [-installed]  show the collections or the installed applications
  refresh            fetch the collections again
  install ID         install or update an application
  remove ID          remove an application
  rollback ID        go back to the previous release
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	commands := map[string]func([]string) error{
		"keygen":   keygen,
		"delegate": delegate,
		"revoke":   revoke,
		"build":    build,
		"verify":   verify,
		"pack":     pack,
		"inspect":  inspect,
		"index":    indexCommand,
		"list":     list,
		"refresh":  refresh,
		"install":  waitFor("Install"),
		"remove":   waitFor("Remove"),
		"rollback": waitFor("Rollback"),
	}
	run, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "sxi:", err)
		os.Exit(1)
	}
}

func readPrivate(path string) (ed25519.PrivateKey, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s is not a raw Ed25519 private key", path)
	}
	return ed25519.PrivateKey(key), nil
}

func readPublic(path string) (ed25519.PublicKey, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is not a raw Ed25519 public key", path)
	}
	return ed25519.PublicKey(key), nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func required(fs *flag.FlagSet, names ...string) error {
	for _, name := range names {
		if fs.Lookup(name).Value.String() == "" {
			return fmt.Errorf("%s: -%s is required", fs.Name(), name)
		}
	}
	return nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("o", "", "key name, writes NAME.key and NAME.pub")
	fs.Parse(args)
	if err := required(fs, "o"); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out+".key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(priv); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return writeNew(*out+".pub", pub)
}

func delegate(args []string) error {
	fs := flag.NewFlagSet("delegate", flag.ExitOnError)
	root := fs.String("root", "", "publisher root private key")
	leaf := fs.String("key", "", "public key being delegated")
	epoch := fs.Uint64("epoch", 1, "delegation epoch")
	days := fs.Int("days", 365, "validity in days")
	purposes := fs.String("purpose", trust.PurposeRelease, "comma separated purposes: release, index")
	out := fs.String("o", "", "output file")
	fs.Parse(args)
	if err := required(fs, "root", "key", "o"); err != nil {
		return err
	}
	rootKey, err := readPrivate(*root)
	if err != nil {
		return err
	}
	leafKey, err := readPublic(*leaf)
	if err != nil {
		return err
	}
	start := time.Now().Add(-time.Hour)
	d := &trust.Delegation{
		Key:       leafKey,
		Epoch:     *epoch,
		NotBefore: uint64(start.Unix()),
		NotAfter:  uint64(start.Add(time.Duration(*days) * 24 * time.Hour).Unix()),
		Purposes:  strings.Split(*purposes, ","),
	}
	payload := trust.EncodeDelegation(d)
	if _, err := trust.ParseDelegation(payload); err != nil {
		return fmt.Errorf("invalid delegation: %w", err)
	}
	return writeNew(*out, cose.Sign(rootKey, cose.DelegationType, payload, false))
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	root := fs.String("root", "", "publisher root private key")
	epoch := fs.Uint64("epoch", 0, "revocation epoch, above every earlier statement")
	minimum := fs.Uint64("min-delegation", 0, "lowest delegation epoch still accepted")
	keys := fs.String("keys", "", "comma separated public key files to revoke")
	out := fs.String("o", "", "output file")
	fs.Parse(args)
	if err := required(fs, "root", "o"); err != nil {
		return err
	}
	if *epoch == 0 {
		return errors.New("revoke: -epoch must be above zero")
	}
	rootKey, err := readPrivate(*root)
	if err != nil {
		return err
	}
	r := &trust.Revocation{Epoch: *epoch, MinimumDelegationEpoch: *minimum}
	if *keys != "" {
		for _, path := range strings.Split(*keys, ",") {
			key, err := readPublic(path)
			if err != nil {
				return err
			}
			r.RevokedKeys = append(r.RevokedKeys, cose.KeyIDOf(key))
		}
	}
	return writeNew(*out, cose.Sign(rootKey, cose.RevocationType, trust.EncodeRevocation(r), false))
}

type specFile struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	Sequence        uint64      `json:"sequence"`
	Entries         []entryFile `json:"entries"`
	Resources       []string    `json:"resources"`
	Icons           []string    `json:"icons"`
	Grants          []string    `json:"grants"`
	Portals         []string    `json:"portals"`
	StateSchema     uint32      `json:"state_schema"`
	RevocationEpoch uint64      `json:"revocation_epoch"`
}

type entryFile struct {
	Arch        string `json:"arch"`
	Image       string `json:"image"`
	Personality string `json:"personality"`
}

func (s *specFile) toSpec() (bundle.Spec, error) {
	spec := bundle.Spec{
		ApplicationID:   s.ID,
		DisplayName:     s.Name,
		ReleaseVersion:  s.Version,
		ReleaseSequence: s.Sequence,
		Resources:       s.Resources,
		Icons:           s.Icons,
		Grants:          s.Grants,
		Portals:         s.Portals,
		RevocationEpoch: s.RevocationEpoch,
	}
	schema := s.StateSchema
	if schema == 0 {
		schema = 1
	}
	spec.State = wire.StatePolicy{Current: schema, MinimumReadable: schema, MaximumReadable: schema}
	architectures := map[string]wire.Architecture{"amd64": wire.AMD64, "arm64": wire.ARM64}
	personalities := map[string]wire.Personality{"linux": wire.Linux, "bsd": wire.BSD}
	for _, e := range s.Entries {
		arch, ok := architectures[e.Arch]
		if !ok {
			return spec, fmt.Errorf("unknown architecture %q", e.Arch)
		}
		personality, ok := personalities[e.Personality]
		if !ok {
			return spec, fmt.Errorf("unsupported personality %q", e.Personality)
		}
		spec.EntryPoints = append(spec.EntryPoints, wire.EntryPoint{Architecture: arch, ImagePath: e.Image, Personality: personality})
	}
	return spec, nil
}

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	specPath := fs.String("spec", "", "application spec (JSON)")
	payload := fs.String("payload", "", "payload directory")
	root := fs.String("root", "", "publisher root public key")
	key := fs.String("key", "", "delegated signing private key")
	certs := fs.String("certs", "", "delegation issued by sxi delegate")
	out := fs.String("o", "", "bundle directory to create")
	fs.Parse(args)
	if err := required(fs, "spec", "payload", "root", "key", "certs", "o"); err != nil {
		return err
	}
	data, err := os.ReadFile(*specPath)
	if err != nil {
		return err
	}
	var sf specFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("%s: %w", *specPath, err)
	}
	spec, err := sf.toSpec()
	if err != nil {
		return err
	}
	rootKey, err := readPublic(*root)
	if err != nil {
		return err
	}
	leafKey, err := readPrivate(*key)
	if err != nil {
		return err
	}
	delegation, err := os.ReadFile(*certs)
	if err != nil {
		return err
	}
	v, err := bundle.Build(*payload, *out, spec, bundle.Signing{Root: rootKey, Leaf: leafKey, Certs: delegation}, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("built %s %s release %d slot %x\n", v.Manifest.ApplicationID, v.Manifest.ReleaseVersion, v.Manifest.ReleaseSequence, v.SlotID)
	return nil
}

func openStore(roots string) (*trust.Store, error) {
	list, err := trust.LoadRoots(roots)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no publisher roots in %s", roots)
	}
	return trust.Open(list, "")
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	roots := fs.String("roots", "", "directory of trusted publisher root public keys (*.pub)")
	fs.Parse(args)
	if err := required(fs, "roots"); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("verify: one bundle directory is required")
	}
	store, err := openStore(*roots)
	if err != nil {
		return err
	}
	v, err := bundle.Verify(fs.Arg(0), store, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("ok %s release %d slot %x publisher %x\n", v.Manifest.ApplicationID, v.Manifest.ReleaseSequence, v.SlotID, v.Manifest.PublisherIdentity)
	return nil
}

func pack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	roots := fs.String("roots", "", "directory of trusted publisher root public keys (*.pub)")
	out := fs.String("o", "", "image file to create")
	fs.Parse(args)
	if err := required(fs, "roots", "o"); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("pack: one bundle directory is required")
	}
	store, err := openStore(*roots)
	if err != nil {
		return err
	}
	v, err := bundle.Verify(fs.Arg(0), store, time.Now())
	if err != nil {
		return err
	}
	p, err := image.Pack(fs.Arg(0), *out, v.SlotID)
	if err != nil {
		return err
	}
	description := map[string]any{
		"id":        v.Manifest.ApplicationID,
		"version":   v.Manifest.ReleaseVersion,
		"sequence":  v.Manifest.ReleaseSequence,
		"slot":      hex.EncodeToString(v.SlotID[:]),
		"release":   hex.EncodeToString(v.Manifest.ReleaseID[:]),
		"publisher": hex.EncodeToString(v.Manifest.PublisherIdentity[:]),
		"size":      p.Size,
		"sha256":    hex.EncodeToString(p.SHA256[:]),
		"verity":    hex.EncodeToString(p.Verity.RootHash[:]),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(description)
}

func inspect(args []string) error {
	if len(args) != 1 {
		return errors.New("inspect: one bundle directory or manifest file is required")
	}
	path := args[0]
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = path + "/" + bundle.ManifestPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m, err := wire.Decode(data)
	if err != nil {
		return err
	}
	type entry struct {
		Path   string `json:"path"`
		Kind   int    `json:"kind"`
		Mode   string `json:"mode"`
		Size   uint64 `json:"size"`
		SHA256 string `json:"sha256"`
	}
	inventory := make([]entry, 0, len(m.Inventory))
	for _, e := range m.Inventory {
		inventory = append(inventory, entry{e.Path, int(e.Kind), fmt.Sprintf("%04o", e.Mode), e.Size, hex.EncodeToString(e.Digest[:])})
	}
	view := map[string]any{
		"id":                   m.ApplicationID,
		"name":                 m.DisplayName,
		"version":              m.ReleaseVersion,
		"sequence":             m.ReleaseSequence,
		"publisher":            hex.EncodeToString(m.PublisherIdentity[:]),
		"application_identity": hex.EncodeToString(m.ApplicationIdentity[:]),
		"release":              hex.EncodeToString(m.ReleaseID[:]),
		"root_key":             hex.EncodeToString(m.Publisher.RootKeyID[:]),
		"signing_key":          hex.EncodeToString(m.Publisher.LeafKeyID[:]),
		"delegation_epoch":     m.Publisher.DelegationEpoch,
		"revocation_epoch":     m.Publisher.RevocationEpoch,
		"entries":              m.EntryPoints,
		"resources":            m.Resources,
		"icons":                m.Icons,
		"grants":               m.Grants,
		"portals":              m.Portals,
		"inventory":            inventory,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(view)
}
