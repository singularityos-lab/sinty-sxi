package manager

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func (m *Manager) autostartDir() string {
	return filepath.Join(m.cfg.Run, "config", "autostart")
}

func (m *Manager) exportAutostart(id, entry, icon string) {
	files, _ := filepath.Glob(filepath.Join(m.appMount(id), "etc", "xdg", "autostart", "*.desktop"))
	for _, f := range files {
		name := filepath.Base(f)
		if !validName(name) || !ownedName(id, strings.TrimSuffix(name, ".desktop")) {
			log.Printf("%s: autostart entry %s is outside the application, skipped", id, name)
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil || len(data) == 0 || len(data) > maxDesktopFile {
			continue
		}
		if err := writeAtomic(filepath.Join(m.autostartDir(), name), rewriteDesktop(data, entry, icon, id), 0o644); err != nil {
			log.Printf("%s: %s: %v", id, name, err)
		}
	}
}

func (m *Manager) unexportAutostart(id string) {
	files, _ := filepath.Glob(filepath.Join(m.autostartDir(), "*.desktop"))
	for _, f := range files {
		if autostartOwner(f) == id {
			os.Remove(f)
		}
	}
}

func autostartOwner(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if ok && key == "X-SXI-Application" {
			return value
		}
	}
	return ""
}
