package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-sxi/cose"
	"github.com/singularityos-lab/sinty-sxi/index"
	"github.com/singularityos-lab/sinty-sxi/trust"
)

func indexCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("index: use init, add, remove or sign")
	}
	switch args[0] {
	case "init":
		return indexInit(args[1:])
	case "add":
		return indexAdd(args[1:])
	case "remove":
		return indexRemove(args[1:])
	case "sign":
		return indexSign(args[1:])
	}
	return fmt.Errorf("index: unknown command %q", args[0])
}

func readIndex(path string) (*index.Index, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ix index.Index
	if err := json.Unmarshal(data, &ix); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &ix, nil
}

func writeIndex(path string, ix *index.Index) error {
	data, err := index.Encode(ix)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func indexInit(args []string) error {
	fs := flag.NewFlagSet("index init", flag.ExitOnError)
	root := fs.String("root", "", "publisher root public key")
	name := fs.String("name", "", "collection name")
	out := fs.String("o", "index.json", "index file to create")
	fs.Parse(args)
	if err := required(fs, "root", "name"); err != nil {
		return err
	}
	key, err := readPublic(*root)
	if err != nil {
		return err
	}
	id := cose.KeyIDOf(key)
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists", *out)
	}
	ix := &index.Index{Schema: index.Schema, Root: hex.EncodeToString(id[:]), Name: *name, Sequence: 1, Generated: time.Now().UTC().Format(time.RFC3339), Apps: []index.App{}}
	data, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(*out, append(data, '\n'))
}

type packResult struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Sequence uint64 `json:"sequence"`
	Slot     string `json:"slot"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Verity   string `json:"verity"`
}

func indexAdd(args []string) error {
	fs := flag.NewFlagSet("index add", flag.ExitOnError)
	path := fs.String("index", "index.json", "index file")
	packed := fs.String("pack", "", "output of sxi pack")
	url := fs.String("url", "", "where the image is downloaded from")
	arch := fs.String("arch", "amd64", "architecture of the image")
	name := fs.String("name", "", "application name")
	summary := fs.String("summary", "", "one line summary")
	description := fs.String("description", "", "longer description")
	icon := fs.String("icon", "", "icon URL")
	categories := fs.String("categories", "", "comma separated categories")
	collections := fs.String("collections", "", "comma separated collections, such as essentials")
	homepage := fs.String("homepage", "", "project page")
	license := fs.String("license", "", "SPDX license")
	keep := fs.Int("keep", 2, "releases kept per architecture")
	fs.Parse(args)
	if err := required(fs, "pack", "url"); err != nil {
		return err
	}
	ix, err := readIndex(*path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*packed)
	if err != nil {
		return err
	}
	var p packResult
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	app := ix.Find(p.ID)
	if app == nil {
		ix.Apps = append(ix.Apps, index.App{ID: p.ID})
		app = &ix.Apps[len(ix.Apps)-1]
	}
	set := func(field *string, value string) {
		if value != "" {
			*field = value
		}
	}
	set(&app.Name, *name)
	set(&app.Summary, *summary)
	set(&app.Description, *description)
	set(&app.Icon, *icon)
	set(&app.Homepage, *homepage)
	set(&app.License, *license)
	if *categories != "" {
		app.Categories = strings.Split(*categories, ",")
	}
	if *collections != "" {
		app.Collections = strings.Split(*collections, ",")
	}
	if app.Name == "" {
		return errors.New("index add: -name is required for a new application")
	}
	kept := []index.Release{{Version: p.Version, Sequence: p.Sequence, URL: *url, Size: p.Size, SHA256: p.SHA256, Verity: p.Verity, Slot: p.Slot, Arch: *arch}}
	count := 1
	for _, r := range app.Releases {
		if r.Arch == *arch {
			if r.Sequence >= p.Sequence {
				return fmt.Errorf("index add: release %d is not newer than %d", p.Sequence, r.Sequence)
			}
			if count >= *keep {
				continue
			}
			count++
		}
		kept = append(kept, r)
	}
	app.Releases = kept
	ix.Sequence++
	ix.Generated = time.Now().UTC().Format(time.RFC3339)
	return writeIndex(*path, ix)
}

func indexRemove(args []string) error {
	fs := flag.NewFlagSet("index remove", flag.ExitOnError)
	path := fs.String("index", "index.json", "index file")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("index remove: one application id is required")
	}
	ix, err := readIndex(*path)
	if err != nil {
		return err
	}
	apps := ix.Apps[:0]
	for _, a := range ix.Apps {
		if a.ID != fs.Arg(0) {
			apps = append(apps, a)
		}
	}
	ix.Apps = apps
	ix.Sequence++
	ix.Generated = time.Now().UTC().Format(time.RFC3339)
	return writeIndex(*path, ix)
}

func indexSign(args []string) error {
	fs := flag.NewFlagSet("index sign", flag.ExitOnError)
	path := fs.String("index", "index.json", "index file")
	key := fs.String("key", "", "delegated index private key")
	certs := fs.String("certs", "", "index delegation issued by sxi delegate -purpose index")
	root := fs.String("root", "", "publisher root public key, to check the result")
	fs.Parse(args)
	if err := required(fs, "key", "certs", "root"); err != nil {
		return err
	}
	ix, err := readIndex(*path)
	if err != nil {
		return err
	}
	if err := writeIndex(*path, ix); err != nil {
		return err
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	leaf, err := readPrivate(*key)
	if err != nil {
		return err
	}
	delegation, err := os.ReadFile(*certs)
	if err != nil {
		return err
	}
	rootKey, err := readPublic(*root)
	if err != nil {
		return err
	}
	signature := cose.Sign(leaf, cose.IndexType, data, true)
	store, err := trust.Open([]trust.Root{{Name: "check", Key: rootKey}}, "")
	if err != nil {
		return err
	}
	if _, err := index.Verify(data, signature, delegation, store, time.Now(), 0); err != nil {
		return fmt.Errorf("index sign: the signed index does not verify: %w", err)
	}
	if err := os.WriteFile(*path+".cose", signature, 0o644); err != nil {
		return err
	}
	certsOut := strings.TrimSuffix(*path, ".json") + ".certs"
	if certsOut == *path {
		certsOut = *path + ".certs"
	}
	return os.WriteFile(certsOut, delegation, 0o644)
}
