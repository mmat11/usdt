package usdt

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/davecgh/go-spew/spew"
)

func init() {
	cache.notes = make(map[string]map[string]map[string]sdtNote)
}

const (
	sdtNoteSec = ".note.stapsdt"
	sdtBaseSec = ".stapsdt.base"
	probesSec  = ".probes"
)

type sdtHeader struct {
	Namesz, Descsz int32
	Type           [4]byte
}

var errNotFound = errors.New("not found")

// SDT notes cache.
type nc struct {
	sync.Mutex
	// [path: [provider: [probe: note]]]
	notes map[string]map[string]map[string]sdtNote
}

var cache nc

type sdtNote struct {
	// SDT note addresses as read in the ELF section.
	location, base, semaphore uint64
	// Location offset
	locationOffset uint64
	// Semaphore offset needed by the Kernel (ref_ctr_offset).
	semaphoreOffsetKernel uint64
	// Semaphore offset in /proc/<pid>/mem.
	semaphoreOffsetUser uint64
	// Provider path on the filesystem.
	path string
	// ELF byteorder.
	bo binary.ByteOrder
}

// Get note from cache, if exists.
//
// Returns errNotFound if not yet loaded.
func (u *USDT) note() (*sdtNote, error) {
	cache.Lock()
	defer cache.Unlock()

	e, ok := cache.notes[u.path]
	if !ok {
		return nil, errNotFound
	}

	prv, ok := e[u.provider]
	if !ok {
		return nil, errNotFound
	}

	n, ok := prv[u.probe]
	if !ok {
		return nil, errNotFound
	}

	return &n, nil
}

// Load SDT notes from main and shared objects for the given process.
func (u *USDT) loadAll() error {
	cache.Lock()
	defer cache.Unlock()

	cache.notes[u.path] = make(map[string]map[string]sdtNote)

	if err := u.load(u.path, regionAddrInfo{0, 0}); err != nil {
		return fmt.Errorf("load main exe notes: %w", err)
	}

	objs, err := sharedObjects(u.pid)
	if err != nil {
		return fmt.Errorf("fetch shared objects: %w", err)
	}

	spew.Dump(objs)

	for obj, info := range objs {
		if err := u.load(obj, info); err != nil {
			return fmt.Errorf("load '%s' notes: %w", obj, err)
		}
	}

	return nil
}

// Load SDT notes from the given ELF file into cache.
//
// www.sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
func (u *USDT) load(obj string, info regionAddrInfo) error {
	osf, err := os.Open(obj)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}

	f, err := elf.NewFile(osf)
	if err != nil {
		// Not a shared object.
		return nil
	}
	defer f.Close()

	sec := f.Section(sdtNoteSec)
	if sec == nil {
		// Notes section not found.
		return nil
	}

	addrsz := 4
	if f.Class == elf.ELFCLASS64 {
		addrsz = 8
	}

	base := sdtBaseAddr(f)

	r := sec.Open()
	for {
		var hdr sdtHeader

		err = binary.Read(r, f.ByteOrder, &hdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read notes: %w", err)
		}

		if int(hdr.Descsz) < (3 * addrsz) {
			return errors.New("invalid SDT note: too short")
		}

		_, err = r.Seek(int64(hdr.Namesz), io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("invalid SDT note: %w", err)
		}

		desc := make([]byte, align4(hdr.Descsz))
		err = binary.Read(r, f.ByteOrder, &desc)
		if err != nil {
			return fmt.Errorf("invalid SDT note: %w", err)
		}

		note := sdtNote{
			location:  f.ByteOrder.Uint64(desc[:addrsz]),
			base:      f.ByteOrder.Uint64(desc[addrsz : 2*addrsz]),
			semaphore: f.ByteOrder.Uint64(desc[2*addrsz : 3*addrsz]),
		}

		if base != 0 {
			diff := base - note.base
			note.location += diff
			note.locationOffset = locationOffset(f, note.location)
			if note.semaphore != 0 {
				note.semaphore += diff
				note.semaphoreOffsetUser = note.semaphore + info.start - info.offset
				note.semaphoreOffsetKernel = semaphoreOffsetKernel(f, note.semaphore)
			}
		}

		idx := 3 * addrsz
		providersz := bytes.IndexByte(desc[idx:], 0)
		provider := string(desc[idx : idx+providersz])

		idx += providersz + 1
		probesz := bytes.IndexByte(desc[idx:], 0)
		probe := string(desc[idx : idx+probesz])

		_, ok := cache.notes[u.path][provider]
		if !ok {
			cache.notes[u.path][provider] = make(map[string]sdtNote)
		}

		note.path = obj
		note.bo = f.ByteOrder
		cache.notes[u.path][provider][probe] = note
	}

	return nil
}

// From the SystemTap wiki about .stapsdt.base:
//
// Nothing about this section itself matters, we just use it as a marker to detect
// prelink address adjustments.
// Each probe note records the link-time address of the .stapsdt.base section alongside
// the probe PC address. The decoder compares the base address stored in the note with
// the .stapsdt.base section's sh_addr.
// Initially these are the same, but the section header will be adjusted by prelink.
// So the decoder applies the difference to the probe PC address to get the correct
// prelinked PC address; the same adjustment is applied to the semaphore address, if any.
func sdtBaseAddr(f *elf.File) uint64 {
	sec := f.Section(sdtBaseSec)
	if sec == nil {
		return 0
	}
	return sec.Addr
}

func locationOffset(f *elf.File, addr uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Vaddr <= addr && addr < (prog.Vaddr+prog.Memsz) {
			return addr - prog.Vaddr + prog.Off
		}
	}
	return addr
}

func semaphoreOffsetKernel(f *elf.File, addr uint64) uint64 {
	sec := f.Section(probesSec)
	if sec != nil {
		return addr - sec.Addr + sec.Offset
	}
	return addr
}

func align4(n int32) uint64 {
	return (uint64(n) + 4 - 1) / 4 * 4
}
