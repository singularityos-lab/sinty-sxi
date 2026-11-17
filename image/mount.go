package image

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mirkobrombin/atomloops/boot"
)

var ErrVerity = errors.New("image: the image does not match its verity root hash")

type Mounted struct {
	Target   string
	Name     string
	DataLoop string
	HashLoop string
}

func Mount(imagePath, hashPath string, rootHash [32]byte, name, target string, exec bool) (*Mounted, error) {
	m := &Mounted{Target: target, Name: name}
	var err error
	if m.DataLoop, err = boot.AttachLoop(imagePath); err != nil {
		return nil, err
	}
	if m.HashLoop, err = boot.AttachLoop(hashPath); err != nil {
		m.release()
		return nil, err
	}
	node, err := openVerity(name, m.DataLoop, m.HashLoop, hex.EncodeToString(rootHash[:]))
	if err != nil {
		m.release()
		return nil, err
	}
	if !boot.HasEROFS(node) {
		m.release()
		return nil, ErrVerity
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		m.release()
		return nil, err
	}
	flags := uintptr(syscall.MS_RDONLY | syscall.MS_NODEV | syscall.MS_NOSUID)
	if !exec {
		flags |= syscall.MS_NOEXEC
	}
	if err := boot.Mount(node, target, "erofs", flags, ""); err != nil {
		m.release()
		return nil, fmt.Errorf("image: %w", err)
	}
	return m, nil
}

var verityOpener = boot.OpenVerity

func openVerity(name, data, hash, root string) (string, error) {
	var node string
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		node, err = verityOpener(name, data, hash, root)
		if err == nil || !errors.Is(err, syscall.EEXIST) {
			return node, err
		}
		time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
	}
	return node, err
}

func (m *Mounted) release() {
	boot.CloseVerity(m.Name)
	if m.HashLoop != "" {
		boot.DetachLoop(m.HashLoop)
	}
	if m.DataLoop != "" {
		boot.DetachLoop(m.DataLoop)
	}
}

func (m *Mounted) Unmount() error {
	if err := syscall.Unmount(m.Target, 0); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	m.release()
	return nil
}

func Release(name, target string, backing ...string) error {
	if err := syscall.Unmount(target, 0); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	if err := boot.CloseVerity(name); err != nil {
		return err
	}
	loops, _ := filepath.Glob("/sys/class/block/loop*")
	for _, loop := range loops {
		dev := "/dev/" + filepath.Base(loop)
		file := boot.LoopBacking(dev)
		for _, b := range backing {
			if file == b {
				boot.DetachLoop(dev)
			}
		}
	}
	return nil
}
