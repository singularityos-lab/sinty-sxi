package manager

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/wire"
)

const maxDesktopFile = 65536

func (m *Manager) applicationsDir() string {
	return filepath.Join(m.cfg.Run, "share", "applications")
}

func (m *Manager) desktopPath(id string) string {
	return filepath.Join(m.applicationsDir(), id+".desktop")
}

func (m *Manager) export(app *Installed) error {
	root := m.appMount(app.ID)
	data, err := os.ReadFile(filepath.Join(root, bundle.ManifestPath))
	if err != nil {
		return err
	}
	man, err := wire.Decode(data)
	if err != nil {
		return err
	}
	entry := ""
	for _, e := range man.EntryPoints {
		if hasEntry(&wire.Manifest{EntryPoints: []wire.EntryPoint{e}}, m.cfg.Arch) {
			entry = filepath.Join(root, e.ImagePath)
		}
	}
	if entry == "" {
		return ErrNoRelease
	}
	var source []byte
	for _, r := range man.Resources {
		if strings.HasSuffix(r, ".desktop") {
			if source, err = os.ReadFile(filepath.Join(root, r)); err != nil {
				return err
			}
			break
		}
	}
	if len(source) == 0 || len(source) > maxDesktopFile {
		source = []byte("[Desktop Entry]\nType=Application\nName=" + man.DisplayName + "\n")
	}
	icon := ""
	for _, i := range man.Icons {
		icon = filepath.Join(root, i)
		break
	}
	if err := m.exportIcon(app.ID, icon); err != nil {
		return err
	}
	out := rewriteDesktop(source, entry, icon, app.ID)
	return writeAtomic(m.desktopPath(app.ID), out, 0o644)
}

func (m *Manager) iconPath(id string) string {
	return filepath.Join(m.cfg.Run, "share", "icons", "hicolor", "scalable", "apps", id+".svg")
}

func (m *Manager) exportIcon(id, icon string) error {
	os.Remove(m.iconPath(id))
	if icon == "" || !strings.HasSuffix(icon, ".svg") {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.iconPath(id)), 0o755); err != nil {
		return err
	}
	return os.Symlink(icon, m.iconPath(id))
}

func (m *Manager) unexport(id string) {
	os.Remove(m.desktopPath(id))
	os.Remove(m.iconPath(id))
}

func rewriteDesktop(source []byte, entry, icon, id string) []byte {
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(source))
	scanner.Buffer(make([]byte, maxDesktopFile), maxDesktopFile)
	group := ""
	wroteMain := false
	mainExec := false
	finishMain := func() {
		if group == "Desktop Entry" && !wroteMain {
			if !mainExec {
				out.WriteString("Exec=" + quote(entry) + "\n")
			}
			out.WriteString("X-SXI-Application=" + id + "\n")
			if icon != "" {
				out.WriteString("Icon=" + icon + "\n")
			}
			wroteMain = true
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			finishMain()
			group = strings.Trim(trimmed, "[]")
			out.WriteString(line + "\n")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			switch strings.TrimSpace(key) {
			case "Exec":
				fields := strings.Fields(value)
				args := ""
				if len(fields) > 1 {
					args = " " + strings.Join(fields[1:], " ")
				}
				out.WriteString("Exec=" + quote(entry) + args + "\n")
				if group == "Desktop Entry" {
					mainExec = true
				}
				continue
			case "TryExec", "Icon", "X-SXI-Application", "DBusActivatable":
				continue
			}
		}
		out.WriteString(line + "\n")
	}
	finishMain()
	return out.Bytes()
}

func quote(path string) string {
	if strings.ContainsAny(path, " \t\"'\\$`") {
		return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$", "`", "\\`").Replace(path) + "\""
	}
	return path
}
