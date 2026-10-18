package bundle

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/singularityos-lab/sinty-sxi/wire"
)

var (
	ErrLink     = errors.New("bundle: links are not allowed")
	ErrSpecial  = errors.New("bundle: only regular files and directories are allowed")
	ErrMount    = errors.New("bundle: the tree crosses a mount point")
	ErrMetadata = errors.New("bundle: extended attributes are not allowed")
	ErrRace     = errors.New("bundle: the tree changed while it was read")
	ErrMode     = errors.New("bundle: object mode is not the required one")
	ErrName     = errors.New("bundle: invalid path")
	ErrTooLarge = errors.New("bundle: the tree is too large")
)

const maxObjects = wire.InventoryMax + 5

type object struct {
	wire.Entry
	content []byte
}

type scanner struct {
	dev     uint64
	strict  bool
	keep    func(path string) int64
	objects []object
}

func scan(dir string, strict bool, keep func(string) int64) ([]object, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("bundle: %s: %w", dir, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	s := &scanner{dev: st.Dev, strict: strict, keep: keep}
	if err := s.directory(fd, ""); err != nil {
		return nil, err
	}
	sort.Slice(s.objects, func(a, b int) bool { return s.objects[a].Path < s.objects[b].Path })
	return s.objects, nil
}

func join(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

func sameObject(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode
}

func (s *scanner) mode(st *unix.Stat_t, kind wire.Kind) (uint16, error) {
	perm := uint16(st.Mode & 0o7777)
	if s.strict {
		if (kind == wire.Directory && perm != 0o555) || (kind == wire.Data && perm != 0o444) || (kind == wire.Image && perm != 0o555) {
			return 0, ErrMode
		}
		return perm, nil
	}
	switch kind {
	case wire.Directory, wire.Image:
		return 0o555, nil
	}
	return 0o444, nil
}

func (s *scanner) directory(fd int, path string) error {
	names, err := readNames(fd)
	if err != nil {
		return err
	}
	for _, name := range names {
		child := join(path, name)
		if !wire.ValidPath(child) {
			return fmt.Errorf("%w: %q", ErrName, child)
		}
		if len(s.objects) >= maxObjects {
			return ErrTooLarge
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if st.Dev != s.dev {
			return fmt.Errorf("%w: %s", ErrMount, child)
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			return fmt.Errorf("%w: %s", ErrLink, child)
		case unix.S_IFDIR:
			if err := s.subdirectory(fd, name, child, &st); err != nil {
				return err
			}
		case unix.S_IFREG:
			if err := s.file(fd, name, child, &st); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %s", ErrSpecial, child)
		}
	}
	return nil
}

func (s *scanner) subdirectory(parent int, name, path string, before *unix.Stat_t) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if !sameObject(before, &st) {
		return fmt.Errorf("%w: %s", ErrRace, path)
	}
	if err := s.noXattrs(fd, path); err != nil {
		return err
	}
	mode, err := s.mode(&st, wire.Directory)
	if err != nil {
		return fmt.Errorf("%w: %s %o", err, path, st.Mode&0o7777)
	}
	digest := sha256.Sum256(nil)
	s.objects = append(s.objects, object{Entry: wire.Entry{Path: path, Kind: wire.Directory, Mode: mode, Digest: digest}})
	return s.directory(fd, path)
}

func (s *scanner) file(parent int, name, path string, before *unix.Stat_t) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if !sameObject(before, &st) || st.Size != before.Size {
		return fmt.Errorf("%w: %s", ErrRace, path)
	}
	if st.Nlink != 1 {
		return fmt.Errorf("%w: %s has %d names", ErrLink, path, st.Nlink)
	}
	if err := s.noXattrs(fd, path); err != nil {
		return err
	}
	kind := wire.Data
	if st.Mode&0o111 != 0 {
		kind = wire.Image
	}
	mode, err := s.mode(&st, kind)
	if err != nil {
		return fmt.Errorf("%w: %s %o", err, path, st.Mode&0o7777)
	}
	h := sha256.New()
	var content []byte
	var reader io.Reader = f
	if limit := s.keep(path); limit > 0 {
		if st.Size > limit {
			return fmt.Errorf("%w: %s", ErrTooLarge, path)
		}
		content = make([]byte, 0, st.Size)
		reader = io.TeeReader(f, writerFunc(func(p []byte) {
			content = append(content, p...)
		}))
	}
	n, err := io.Copy(h, reader)
	if err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if n != st.Size || after.Size != st.Size || after.Mtim != st.Mtim || after.Ctim != st.Ctim {
		return fmt.Errorf("%w: %s", ErrRace, path)
	}
	var digest [wire.DigestSize]byte
	copy(digest[:], h.Sum(nil))
	s.objects = append(s.objects, object{
		Entry:   wire.Entry{Path: path, Kind: kind, Mode: mode, Size: uint64(n), Digest: digest},
		content: content,
	})
	return nil
}

type writerFunc func([]byte)

func (w writerFunc) Write(p []byte) (int, error) {
	w(p)
	return len(p), nil
}

func readNames(fd int) ([]string, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "")
	defer f.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func (s *scanner) noXattrs(fd int, path string) error {
	if !s.strict {
		return nil
	}
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			return nil
		}
		return err
	}
	if size != 0 {
		return fmt.Errorf("%w: %s", ErrMetadata, path)
	}
	return nil
}
