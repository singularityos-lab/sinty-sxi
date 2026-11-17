package image

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestOpenVerityRetriesOnNodeRace(t *testing.T) {
	calls := 0
	orig := verityOpener
	verityOpener = func(name, data, hash, root string) (string, error) {
		calls++
		if calls < 3 {
			return "", fmt.Errorf("node /dev/mapper/%s: %w", name, syscall.EEXIST)
		}
		return "/dev/mapper/" + name, nil
	}
	t.Cleanup(func() { verityOpener = orig })
	node, err := openVerity("sxi-stage-x", "/dev/loop0", "/dev/loop1", "00")
	if err != nil || node != "/dev/mapper/sxi-stage-x" || calls != 3 {
		t.Fatalf("node=%q err=%v calls=%d", node, err, calls)
	}
}

func TestOpenVerityKeepsOtherErrors(t *testing.T) {
	calls := 0
	orig := verityOpener
	verityOpener = func(name, data, hash, root string) (string, error) {
		calls++
		return "", errors.New("invalid root hash")
	}
	t.Cleanup(func() { verityOpener = orig })
	if _, err := openVerity("n", "d", "h", "r"); err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
