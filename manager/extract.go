package manager

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"sync"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/image"
)

type ExtractMounter struct {
	// Admit names a helper that seals an extracted application and admits
	// its code on systems that enforce code signatures.
	Admit   string
	mu      sync.Mutex
	mounted map[string]string
}

func (e *ExtractMounter) Mount(imagePath, hashPath string, rootHash [32]byte, name, target string, exec bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mounted == nil {
		e.mounted = map[string]string{}
	}
	if _, ok := e.mounted[name]; ok {
		return errors.New("manager: " + name + " is already in use")
	}
	tree, err := os.ReadFile(hashPath)
	if err != nil {
		return err
	}
	if len(tree) < image.BlockSize {
		return image.ErrVerity
	}
	f, err := os.Open(imagePath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	var salt [32]byte
	var uuid [16]byte
	copy(salt[:], tree[88:120])
	copy(uuid[:], tree[16:32])
	v, err := image.Format(f, info.Size(), salt, uuid)
	if err != nil {
		return err
	}
	if v.RootHash != rootHash || !bytes.Equal(v.Tree, tree) {
		return image.ErrVerity
	}
	if err := image.Extract(imagePath, target); err != nil {
		return err
	}
	if e.Admit != "" && exec {
		real, err := filepath.EvalSymlinks(target)
		if err != nil {
			os.RemoveAll(target)
			return err
		}
		if out, err := osexec.Command(e.Admit, "mount", real).CombinedOutput(); err != nil {
			os.RemoveAll(target)
			return fmt.Errorf("manager: admit %s: %v: %s", target, err, out)
		}
	}
	e.mounted[name] = target
	return nil
}

func (e *ExtractMounter) Release(name, target string, backing ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.mounted, name)
	if _, err := os.Lstat(target); err != nil {
		return nil
	}
	if e.Admit != "" {
		if real, err := filepath.EvalSymlinks(target); err == nil {
			osexec.Command(e.Admit, "unmount", real).Run()
		}
	}
	bundle.Unseal(target)
	return os.RemoveAll(target)
}
