package usdt

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// USDT is a userspace statically defined tracepoint.
type USDT struct {
	pid                   int
	path, provider, probe string
	uprobe                link.Link
	close                 *func() error
}

// Close closes the underlying uprobe.
func (u *USDT) Close() error {
	if err := u.uprobe.Close(); err != nil {
		return fmt.Errorf("close uprobe: %w", err)
	}
	if u.close != nil {
		return (*u.close)()
	}
	return nil
}

// New opens an USDT for the provided provider, probe and pid and attaches
// it to prog.
func New(prog *ebpf.Program, provider, probe string, pid int) (*USDT, error) {
	if pid < 1 {
		return nil, errors.New("invalid pid")
	}

	u := &USDT{
		pid:      pid,
		probe:    probe,
		provider: provider,
		path:     fmt.Sprintf("/proc/%d/exe", pid),
	}

	note, err := u.note()
	if err != nil {
		if errors.Is(err, errNotFound) {
			if err := u.loadAll(); err != nil {
				return nil, fmt.Errorf("load all notes: %w", err)
			}
		}

		// Cache should now be ready, retry.
		note, err = u.note()
		if err != nil {
			return nil, fmt.Errorf("load note: probe %s not found in provider %s: %w", probe, provider, err)
		}
	}

	e, err := link.OpenExecutable(note.path)
	if err != nil {
		return nil, fmt.Errorf("open executable: %w", err)
	}

	sym := fmt.Sprintf("usdt_%s_%s", provider, probe)
	opts := &link.UprobeOptions{
		PID:    pid,
		Offset: note.locationOffset,
		// Kernel 4.20+.
		RefCtrOffset: note.semaphoreOffsetKernel,
	}
	up, err := e.Uprobe(sym, prog, opts)
	if err != nil {
		if !errors.Is(err, link.ErrNotSupported) {
			return nil, fmt.Errorf("create uprobe (ref_ctr_offset): %w", err)
		}

		// Fallback to manual semaphore handling.
		opts.RefCtrOffset = 0
		up, err = e.Uprobe(sym, prog, opts)
		if err != nil {
			return nil, fmt.Errorf("create uprobe: %w", err)
		}

		if note.semaphore != 0 {
			if err := updateSemaphore(note, u.pid, true); err != nil {
				return nil, fmt.Errorf("inc semaphore: %w", err)
			}

			closer := func() error {
				return updateSemaphore(note, u.pid, false)
			}
			u.close = &closer
		}
	}

	u.uprobe = up

	return u, nil
}
