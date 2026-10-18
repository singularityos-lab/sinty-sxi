package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const corpus = "testdata/v1"

func table(t *testing.T, name string) [][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpus, name))
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]string
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if i == 0 {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows
}

func hexFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpus, name))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return decoded
}

func failureOf(err error) Failure {
	if err == nil {
		return OK
	}
	var rejected *Error
	if errors.As(err, &rejected) {
		return rejected.Failure
	}
	return Internal
}

func TestCorpus(t *testing.T) {
	rows := table(t, "cases.tsv")
	if len(rows) == 0 {
		t.Fatal("empty corpus")
	}
	for _, row := range rows {
		outcome, failure, path, digest := row[0], row[1], row[2], row[3]
		t.Run(path, func(t *testing.T) {
			data := hexFile(t, path)
			if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != digest {
				t.Fatalf("fixture digest mismatch")
			}
			_, err := Decode(data)
			got := failureOf(err)
			if got.String() != failure {
				t.Fatalf("got %s, want %s", got, failure)
			}
			if (outcome == "accept") != (got == OK) {
				t.Fatalf("outcome %s with %s", outcome, got)
			}
		})
	}
}

func TestProbes(t *testing.T) {
	for _, row := range table(t, "probes.tsv") {
		failure, recipe, digest := row[0], row[2], row[4]
		if recipe != "a0 + 00 * 262144" {
			t.Fatalf("unknown probe recipe %q", recipe)
		}
		data := append([]byte{0xa0}, make([]byte, ManifestMax)...)
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != digest {
			t.Fatalf("probe digest mismatch")
		}
		if got := failureOf(func() error { _, err := Decode(data); return err }()); got.String() != failure {
			t.Fatalf("got %s, want %s", got, failure)
		}
	}
}

func TestVectors(t *testing.T) {
	m, err := Decode(hexFile(t, "fixtures/accept/minimal-native-amd64.hex"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, row := range table(t, "vectors.tsv") {
		want[row[0]] = row[1]
	}
	got := map[string][DigestSize]byte{
		"publisher_identity":   m.PublisherIdentity,
		"application_identity": m.ApplicationIdentity,
		"payload_digest":       m.PayloadDigest,
		"release_id":           m.ReleaseID,
	}
	for name, value := range got {
		if hex.EncodeToString(value[:]) != want[name] {
			t.Errorf("%s = %x, want %s", name, value, want[name])
		}
	}
	if !bytes.Equal(InventoryRecords(payloadDomain, m.Inventory), hexFile(t, "vectors/payload-records.hex")) {
		t.Error("payload preimage differs from the vector")
	}
	slot := hexFile(t, "vectors/slot-records.hex")
	if sum := sha256.Sum256(slot); hex.EncodeToString(sum[:]) != want["slot_id"] {
		t.Error("slot vector digest differs")
	}
	if !bytes.HasPrefix(slot, []byte(slotDomain)) {
		t.Error("slot vector has the wrong domain")
	}
}

func TestReleasePreimage(t *testing.T) {
	data := hexFile(t, "fixtures/accept/minimal-native-amd64.hex")
	if !bytes.Equal(ReleasePreimage(data), hexFile(t, "vectors/release-preimage.hex")) {
		t.Fatal("release preimage differs from the vector")
	}
}

func TestDecodedFields(t *testing.T) {
	m, err := Decode(hexFile(t, "fixtures/accept/compat-linux-arm64.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.EntryPoints) != 1 || m.EntryPoints[0].Personality != Linux || m.EntryPoints[0].Architecture != ARM64 {
		t.Fatalf("entry points = %+v", m.EntryPoints)
	}
	if m.EntryPoints[0].ABI != nil {
		t.Fatal("compatibility entry carries a native ABI")
	}
	if entry := m.Find(m.EntryPoints[0].ImagePath); entry == nil || entry.Kind != Image {
		t.Fatal("entry image is not an inventory image")
	}
}

func FuzzDecode(f *testing.F) {
	for _, dir := range []string{"accept", "reject"} {
		names, _ := filepath.Glob(filepath.Join(corpus, "fixtures", dir, "*.hex"))
		for _, name := range names {
			data, _ := os.ReadFile(name)
			if decoded, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil {
				f.Add(decoded)
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Decode(data)
		if err == nil && PayloadDigestOf(m.Inventory) != m.PayloadDigest {
			t.Fatal("accepted a manifest with a wrong payload digest")
		}
	})
}

func TestEncodeRoundTrip(t *testing.T) {
	names, err := filepath.Glob(filepath.Join(corpus, "fixtures", "accept", "*.hex"))
	if err != nil || len(names) == 0 {
		t.Fatal("no accepted fixtures")
	}
	for _, name := range names {
		data := hexFile(t, strings.TrimPrefix(name, corpus+"/"))
		m, err := Decode(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(Encode(m), data) {
			t.Errorf("%s: encoding differs from the fixture", filepath.Base(name))
		}
	}
}
