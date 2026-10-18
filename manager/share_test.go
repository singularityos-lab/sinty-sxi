package manager

import (
	"os"
	"path/filepath"
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
