package manager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMimeCacheListsExportedHandlers(t *testing.T) {
	m := &Manager{cfg: Config{Run: t.TempDir()}}
	os.MkdirAll(m.applicationsDir(), 0o755)
	os.WriteFile(m.desktopPath("org.example.reader"), []byte("[Desktop Entry]\nName=Reader\nMimeType=application/pdf;application/x-pdf;\n[Desktop Action new]\nMimeType=text/plain;\n"), 0o644)
	os.WriteFile(m.desktopPath("org.example.view"), []byte("[Desktop Entry]\nName=View\nMimeType=image/png;application/pdf;;bogus;\n"), 0o644)
	if err := m.refreshMimeCache(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(m.mimeCachePath())
	if err != nil {
		t.Fatal(err)
	}
	want := "[MIME Cache]\napplication/pdf=org.example.reader.desktop;org.example.view.desktop;\napplication/x-pdf=org.example.reader.desktop;\nimage/png=org.example.view.desktop;\n"
	if string(data) != want {
		t.Fatalf("cache:\n%s\nwant:\n%s", data, want)
	}
	m.unexport("org.example.reader")
	m.unexport("org.example.view")
	if _, err := os.Stat(m.mimeCachePath()); !os.IsNotExist(err) {
		t.Fatalf("cache left behind with no applications: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.applicationsDir())); err != nil {
		t.Fatal(err)
	}
}
