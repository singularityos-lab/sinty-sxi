package main

import (
	"os"
	"strconv"
	"syscall"
	"testing"
)

func threadState(t *testing.T) (nices, classes []int) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Skip("no /proc")
	}
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		prio, err := syscall.Getpriority(syscall.PRIO_PROCESS, tid)
		if err != nil {
			continue
		}
		class, _, _ := syscall.Syscall(syscall.SYS_IOPRIO_GET, ioprioWhoProcess, uintptr(tid), 0)
		nices = append(nices, 20-prio)
		classes = append(classes, int(class>>ioprioClassShift))
	}
	return
}

func TestFollowedOperationRunsAtNormalPriority(t *testing.T) {
	s := &service{busy: map[string]bool{}, follow: map[string]bool{}}
	s.busy["app"] = true
	s.applyPriority()
	nices, classes := threadState(t)
	for i := range nices {
		if nices[i] != backgroundNice || classes[i] != ioprioClassIdle {
			t.Fatalf("unfollowed operation: nice %d class %d", nices[i], classes[i])
		}
	}
	s.follow["app"] = true
	s.applyPriority()
	_, classes = threadState(t)
	for _, c := range classes {
		if c == ioprioClassIdle {
			t.Fatal("followed operation still at idle disk priority")
		}
	}
	delete(s.follow, "app")
	s.applyPriority()
	_, classes = threadState(t)
	for _, c := range classes {
		if c != ioprioClassIdle {
			t.Fatal("operation did not drop again")
		}
	}
}
