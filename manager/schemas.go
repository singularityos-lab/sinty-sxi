package manager

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

const maxSchemaFile = 1 << 20

var ErrSchema = errors.New("manager: the schema reaches outside its application")

func (m *Manager) schemasDir() string {
	return filepath.Join(m.cfg.Run, "share", "glib-2.0", "schemas")
}

func ownedName(id, name string) bool {
	return name == id || strings.HasPrefix(name, id+".")
}

func checkSchema(id string, data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	path := "/" + strings.ReplaceAll(id, ".", "/") + "/"
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "schema", "enum", "flags":
			for _, a := range start.Attr {
				switch a.Name.Local {
				case "id":
					if !ownedName(id, a.Value) {
						return fmt.Errorf("%w: %s", ErrSchema, a.Value)
					}
				case "path":
					if !strings.HasPrefix(a.Value, path) {
						return fmt.Errorf("%w: %s", ErrSchema, a.Value)
					}
				case "extends", "list-of":
					if !ownedName(id, a.Value) {
						return fmt.Errorf("%w: %s", ErrSchema, a.Value)
					}
				}
			}
		}
	}
}

func (m *Manager) appSchemas(id string) [][]byte {
	root := m.appMount(id)
	data, err := os.ReadFile(filepath.Join(root, bundle.ManifestPath))
	if err != nil {
		return nil
	}
	man, err := wire.Decode(data)
	if err != nil {
		return nil
	}
	var out [][]byte
	candidates := append([]string(nil), man.Resources...)
	own, _ := filepath.Glob(filepath.Join(root, "share", "glib-2.0", "schemas", "*.gschema.xml"))
	for _, path := range own {
		if rel, err := filepath.Rel(root, path); err == nil && !contains(candidates, rel) {
			candidates = append(candidates, rel)
		}
	}
	for _, r := range candidates {
		if !strings.HasSuffix(r, ".gschema.xml") {
			continue
		}
		info, err := os.Stat(filepath.Join(root, r))
		if err != nil || info.Size() > maxSchemaFile {
			continue
		}
		schema, err := os.ReadFile(filepath.Join(root, r))
		if err != nil {
			continue
		}
		if err := checkSchema(id, schema); err != nil {
			log.Printf("%s: %s skipped: %v", id, r, err)
			continue
		}
		out = append(out, schema)
	}
	return out
}

func (m *Manager) exportSchemas() error {
	dir := m.schemasDir()
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	count := 0
	for _, app := range m.reg.list() {
		for i, schema := range m.appSchemas(app.ID) {
			name := fmt.Sprintf("%s.%d.gschema.xml", app.ID, i)
			if err := os.WriteFile(filepath.Join(dir, name), schema, 0o644); err != nil {
				return err
			}
			count++
		}
	}
	if count == 0 {
		return nil
	}
	if output, err := exec.Command("glib-compile-schemas", dir).CombinedOutput(); err != nil {
		os.Remove(filepath.Join(dir, "gschemas.compiled"))
		return fmt.Errorf("manager: glib-compile-schemas: %v: %s", err, output)
	}
	return nil
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
