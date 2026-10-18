package image

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

func TestLevels(t *testing.T) {
	for blocks, want := range map[uint64]int{1: 0, 2: 1, 128: 1, 129: 2, 16384: 2, 16385: 3} {
		if got := levels(blocks); got != want {
			t.Errorf("levels(%d) = %d, want %d", blocks, got, want)
		}
	}
}

func TestMatchesVeritysetup(t *testing.T) {
	tool, err := exec.LookPath("veritysetup")
	if err != nil {
		t.Skip("veritysetup is not installed")
	}
	rootLine := regexp.MustCompile(`Root hash:\s+([0-9a-f]{64})`)
	for _, blocks := range []int{1, 2, 127, 128, 129, 300, 16385} {
		t.Run(fmt.Sprint(blocks), func(t *testing.T) {
			dir := t.TempDir()
			data := make([]byte, blocks*BlockSize)
			rand.Read(data)
			dataPath, hashPath := filepath.Join(dir, "data"), filepath.Join(dir, "hash")
			if err := os.WriteFile(dataPath, data, 0o644); err != nil {
				t.Fatal(err)
			}
			var salt [32]byte
			var uuid [16]byte
			rand.Read(salt[:])
			rand.Read(uuid[:])
			uuid[6] = uuid[6]&0x0f | 0x40
			uuid[8] = uuid[8]&0x3f | 0x80
			u := hex.EncodeToString(uuid[:])
			formatted := fmt.Sprintf("%s-%s-%s-%s-%s", u[:8], u[8:12], u[12:16], u[16:20], u[20:])
			out, err := exec.Command(tool, "format", dataPath, hashPath, "--hash=sha256", "--format=1",
				"--data-block-size=4096", "--hash-block-size=4096", "--salt="+hex.EncodeToString(salt[:]),
				"--uuid="+formatted).CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			m := rootLine.FindSubmatch(out)
			if m == nil {
				t.Fatalf("no root hash in %s", out)
			}
			v, err := Format(bytes.NewReader(data), int64(len(data)), salt, uuid)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(v.RootHash[:]) != string(m[1]) {
				t.Fatalf("root %x, veritysetup %s", v.RootHash, m[1])
			}
			want, err := os.ReadFile(hashPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(v.Tree, want) {
				t.Fatalf("hash device differs: %d bytes, veritysetup %d", len(v.Tree), len(want))
			}
		})
	}
}
