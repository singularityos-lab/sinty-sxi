package manager

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/singularityos-lab/sinty-sxi/bundle"
	"github.com/singularityos-lab/sinty-sxi/image"
)

type ExtractMounter struct {
	// Admit names a helper that seals an extracted application and admits
	// its code on systems that enforce code signatures.
	Admit      string
	MountTable string
	mu         sync.Mutex
	mounted    map[string]string
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
	if e.Admit == "" || !exec {
		if err := image.Extract(imagePath, target); err != nil {
			return err
		}
		e.mounted[name] = target
		return nil
	}
	dir := releaseTree(target, name)
	bundle.Unseal(dir)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := image.Extract(imagePath, dir); err != nil {
		os.RemoveAll(dir)
		return err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		os.RemoveAll(dir)
		return err
	}
	realTree, err := filepath.EvalSymlinks(dir)
	if err != nil {
		os.RemoveAll(dir)
		return err
	}
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		os.RemoveAll(dir)
		return err
	}
	if out, err := osexec.Command(e.Admit, "mount", realTree, realTarget).CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		return fmt.Errorf("manager: admit %s: %v: %s", target, err, out)
	}
	e.mounted[name] = target
	e.prune(target, dir)
	return nil
}

func (e *ExtractMounter) prune(target, keep string) {
	table := e.MountTable
	if table == "" {
		table = "/proc/mounts"
	}
	b, err := os.ReadFile(table)
	if err != nil {
		return
	}
	var sources []string
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			sources = append(sources, f[0])
		}
	}
	trees, _ := filepath.Glob(filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+"@*"))
	for _, tree := range trees {
		if tree == keep {
			continue
		}
		real, err := filepath.EvalSymlinks(tree)
		if err != nil {
			continue
		}
		busy := false
		for _, src := range sources {
			if src == real || strings.HasSuffix(src, real) {
				busy = true
				break
			}
		}
		if !busy {
			bundle.Unseal(tree)
			os.RemoveAll(tree)
		}
	}
}

// releaseTree is where an image is extracted before it is mounted onto
// target: one tree per release slot, so a new release never writes into the
// tree a running copy of the application still uses.
func releaseTree(target, name string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+"@"+name)
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
			if osexec.Command(e.Admit, "unmount", real).Run() != nil {
				return errors.New("manager: " + target + " is still in use")
			}
		}
		tree := releaseTree(target, name)
		bundle.Unseal(tree)
		os.RemoveAll(tree)
	}
	bundle.Unseal(target)
	return os.RemoveAll(target)
}
