package manager

import (
	"bytes"
	"errors"
	"os"
	"sync"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/image"
)

type ExtractMounter struct {
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
	bundle.Unseal(target)
	return os.RemoveAll(target)
}
