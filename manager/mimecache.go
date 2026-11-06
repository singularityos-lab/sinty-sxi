package manager

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func (m *Manager) mimeCachePath() string {
	return filepath.Join(m.applicationsDir(), "mimeinfo.cache")
}

func (m *Manager) refreshMimeCache() error {
	files, err := filepath.Glob(filepath.Join(m.applicationsDir(), "*.desktop"))
	if err != nil {
		return err
	}
	handlers := map[string][]string{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > maxDesktopFile {
			continue
		}
		name := filepath.Base(path)
		for _, mime := range desktopMimeTypes(data) {
			handlers[mime] = append(handlers[mime], name)
		}
	}
	if len(handlers) == 0 {
		err := os.Remove(m.mimeCachePath())
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	mimes := make([]string, 0, len(handlers))
	for mime := range handlers {
		mimes = append(mimes, mime)
	}
	sort.Strings(mimes)
	var out bytes.Buffer
	out.WriteString("[MIME Cache]\n")
	for _, mime := range mimes {
		names := handlers[mime]
		sort.Strings(names)
		out.WriteString(mime + "=" + strings.Join(names, ";") + ";\n")
	}
	return writeAtomic(m.mimeCachePath(), out.Bytes(), 0o644)
}

func desktopMimeTypes(data []byte) []string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, maxDesktopFile), maxDesktopFile)
	group := ""
	seen := map[string]bool{}
	var mimes []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			group = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || group != "Desktop Entry" || strings.TrimSpace(key) != "MimeType" {
			continue
		}
		for _, mime := range strings.Split(value, ";") {
			mime = strings.TrimSpace(mime)
			if mime == "" || !strings.Contains(mime, "/") || strings.ContainsAny(mime, "=[]\n") || seen[mime] {
				continue
			}
			seen[mime] = true
			mimes = append(mimes, mime)
		}
	}
	return mimes
}
