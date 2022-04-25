package usdt

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Info eventually needed to calculate semaphore offset (userspace).
type regionAddrInfo struct {
	start, offset uint64
}

// Fetch all shared objects from /proc/<pid>/maps.
func sharedObjects(pid int) (map[string]*regionAddrInfo, error) {
	objs := make(map[string]*regionAddrInfo)

	m, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return objs, err
	}
	defer m.Close()

	s := bufio.NewScanner(m)
	for s.Scan() {
		ss := strings.Split(s.Text(), " ")
		path := ss[len(ss)-1]

		// Inode.
		if ss[4] == "0" {
			// Region not mapped from a file.
			continue
		}

		objs[path] = nil

		// Perms.
		if string(ss[1][1]) != "w" {
			// Skip non writable regions.
			continue
		}

		regionAddr := strings.Split(ss[0], "-")
		start, err := strconv.ParseUint(regionAddr[0], 16, 64)
		if err != nil {
			return objs, err
		}

		off, err := strconv.ParseUint(ss[2], 16, 64)
		if err != nil {
			return objs, err
		}

		objs[path] = &regionAddrInfo{start, off}
	}

	return objs, nil
}

func updateSemaphore(note *sdtNote, pid int, inc bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.PtraceAttach(pid); err != nil {
		return fmt.Errorf("ptrace attach: %w", err)
	}
	defer func() { _ = unix.PtraceDetach(pid) }()

	for {
		_, err := syscall.Wait4(pid, nil, 0, nil)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}

	// Number of expected bytes for unsigned short.
	b := 2

	semb := make([]byte, b)
	c, err := unix.PtracePeekData(pid, uintptr(note.semaphoreOffsetUser), semb)
	if err != nil {
		return fmt.Errorf("ptrace peek: %w", err)
	}
	if c != b {
		return fmt.Errorf("ptrace peek: wrong number of bytes read: %d", c)
	}

	sem := note.bo.Uint16(semb)
	// In normal cases, this should never underflow.
	if inc {
		sem += 1
	} else {
		sem -= 1
	}
	note.bo.PutUint16(semb, sem)

	c, err = unix.PtracePokeData(pid, uintptr(note.semaphoreOffsetUser), semb)
	if err != nil {
		return fmt.Errorf("ptrace poke: %w", err)
	}
	if c != b {
		return fmt.Errorf("ptrace poke: wrong number of bytes written: %d", c)
	}

	return nil
}
