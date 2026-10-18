package image

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const saltDomain = "SIX-SXI-VERITY-v1\x00"

type Packed struct {
	Path   string
	Size   int64
	SHA256 [sha256.Size]byte
	Verity *Verity
}

func SaltFor(slotID [sha256.Size]byte) (salt [32]byte, uuid [16]byte) {
	salt = sha256.Sum256(append([]byte(saltDomain), slotID[:]...))
	sum := sha256.Sum256(salt[:])
	copy(uuid[:], sum[:16])
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80
	return salt, uuid
}

func uuidString(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:])
}

func Pack(bundleDir, out string, slotID [sha256.Size]byte) (*Packed, error) {
	if _, err := os.Lstat(out); err == nil {
		return nil, fmt.Errorf("image: %s already exists", out)
	}
	salt, uuid := SaltFor(slotID)
	cmd := exec.Command("mkfs.erofs", "-z", "lz4hc,9", "-E", "ztailpacking", "-T0", "--all-root",
		"--ignore-mtime", "-x", "-1", "-U", uuidString(uuid), out, bundleDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(out)
		return nil, fmt.Errorf("image: mkfs.erofs: %v: %s", err, output)
	}
	return Describe(out, salt, uuid)
}

func Describe(path string, salt [32]byte, uuid [16]byte) (*Packed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	p := &Packed{Path: path, Size: info.Size()}
	copy(p.SHA256[:], h.Sum(nil))
	if p.Verity, err = Format(f, info.Size(), salt, uuid); err != nil {
		return nil, err
	}
	return p, nil
}

func Extract(image, dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	output, err := exec.Command("fsck.erofs", "--extract="+dir, "--preserve-perms", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("image: fsck.erofs: %v: %s", err, output)
	}
	return nil
}
