package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportShareRefreshesIconThemes(t *testing.T) {
	run := t.TempDir()
	m := &Manager{cfg: Config{Run: run}}
	for _, id := range []string{"org.example.one", "org.example.two"} {
		apps := filepath.Join(m.appMount(id), "share", "icons", "hicolor", "scalable", "apps")
		os.MkdirAll(apps, 0o755)
		os.WriteFile(filepath.Join(apps, id+".svg"), []byte("<svg/>"), 0o644)
	}
	m.exportShare("org.example.one")
	theme := filepath.Join(m.shareDir(), "icons", "hicolor")
	old := time.Now().Add(-time.Hour)
	os.Chtimes(theme, old, old)
	m.exportShare("org.example.two")
	if _, err := os.Lstat(filepath.Join(theme, "scalable", "apps", "org.example.two.svg")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(theme)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().After(old.Add(time.Minute)) {
		t.Fatalf("theme directory not refreshed after a second export: %v", info.ModTime())
	}
	os.Chtimes(theme, old, old)
	m.unexportShare("org.example.two")
	info, _ = os.Stat(theme)
	if !info.ModTime().After(old.Add(time.Minute)) {
		t.Fatalf("theme directory not refreshed after removal: %v", info.ModTime())
	}
}

func TestAutostartEntriesFollowTheApplication(t *testing.T) {
	run := t.TempDir()
	m := &Manager{cfg: Config{Run: run}}
	id := "org.example.tasks"
	dir := filepath.Join(m.appMount(id), "etc", "xdg", "autostart")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, id+".reminders.desktop"), []byte("[Desktop Entry]\nType=Application\nName=Reminders\nExec=tasks --background\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "org.other.desktop"), []byte("[Desktop Entry]\nType=Application\nName=Other\nExec=other\n"), 0o644)
	entry := filepath.Join(m.appMount(id), "bin", "tasks")
	m.exportAutostart(id, entry, "")
	data, err := os.ReadFile(filepath.Join(m.autostartDir(), id+".reminders.desktop"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Exec="+entry+" --background\n") || !strings.Contains(string(data), "X-SXI-Application="+id+"\n") {
		t.Fatalf("unexpected entry:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(m.autostartDir(), "org.other.desktop")); err == nil {
		t.Fatal("an entry named after another application was exported")
	}
	m.unexport(id)
	if _, err := os.Stat(filepath.Join(m.autostartDir(), id+".reminders.desktop")); err == nil {
		t.Fatal("autostart entry left behind after removal")
	}
}
