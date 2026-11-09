package main

import (
	"os"
	"strconv"
	"syscall"
)

const (
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3
	ioprioClassShift = 13
	backgroundNice   = 19
)

func setBackground(low bool) {
	nice, io := 0, 0
	if low {
		nice, io = backgroundNice, ioprioClassIdle<<ioprioClassShift
	}
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return
	}
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		syscall.Setpriority(syscall.PRIO_PROCESS, tid, nice)
		syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), uintptr(io))
	}
}
