package manager

import (
	"bufio"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var shareDirs = []string{
	"icons",
	"singularity/search-providers",
	"singularity/app-settings",
	"singularity/capabilities",
	"singularity/share-targets",
	"singularity/files-actions",
	"singularity/widgets",
}

func (m *Manager) shareDir() string {
	return filepath.Join(m.cfg.Run, "share")
}

func link(target, path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.Symlink(target, path)
}

func validName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") {
		return false
	}
	for _, r := range name {
		if !(r == '.' || r == '-' || r == '_' || r == '+' || r == '@' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func ownedService(id, path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	name := ""
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if ok && strings.TrimSpace(key) == "Name" {
			name = strings.TrimSpace(value)
		}
	}
	return ownedName(id, name)
}

func (m *Manager) exportShare(id string) {
	root := m.appMount(id)
	share := filepath.Join(root, "share")
	for _, dir := range shareDirs {
		base := filepath.Join(share, dir)
		filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !validName(d.Name()) {
				return nil
			}
			rel, err := filepath.Rel(share, path)
			if err != nil {
				return nil
			}
			if err := link(path, filepath.Join(m.shareDir(), rel)); err != nil {
				log.Printf("%s: %s: %v", id, rel, err)
			}
			return nil
		})
	}
	services, _ := filepath.Glob(filepath.Join(share, "dbus-1", "services", "*.service"))
	for _, s := range services {
		if !ownedService(id, s) {
			log.Printf("%s: %s names a service outside the application, skipped", id, filepath.Base(s))
			continue
		}
		link(s, filepath.Join(m.shareDir(), "dbus-1", "services", filepath.Base(s)))
	}
	widgets, _ := filepath.Glob(filepath.Join(root, "lib", "singularity", "widgets", "*.so"))
	for _, w := range widgets {
		link(w, filepath.Join(m.shareDir(), "singularity", "widgets", filepath.Base(w)))
	}
	plugins, _ := os.ReadDir(filepath.Join(root, "lib", "singularity", "plugins"))
	for _, p := range plugins {
		if p.IsDir() && validName(p.Name()) {
			link(filepath.Join(root, "lib", "singularity", "plugins", p.Name()), filepath.Join(m.shareDir(), "singularity", "plugins", p.Name()))
		}
	}
	m.touchIconThemes()
}

func (m *Manager) touchIconThemes() {
	icons := filepath.Join(m.shareDir(), "icons")
	themes, err := os.ReadDir(icons)
	if err != nil {
		return
	}
	now := time.Now()
	os.Chtimes(icons, now, now)
	for _, t := range themes {
		if t.IsDir() {
			os.Chtimes(filepath.Join(icons, t.Name()), now, now)
		}
	}
}

func (m *Manager) unexportShare(id string) {
	prefix := m.appMount(id) + string(filepath.Separator)
	filepath.WalkDir(m.shareDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		if target, err := os.Readlink(path); err == nil && strings.HasPrefix(target, prefix) {
			os.Remove(path)
		}
		return nil
	})
	m.touchIconThemes()
}
