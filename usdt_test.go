package usdt_test

import (
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mmat11/usdt"
)

func TestUSDT(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		cmd      *exec.Cmd
		provider string
		probe    string
		sleep    time.Duration
	}{
		{
			"Python (builtin notes)",
			exec.Command(
				"python",
				"-c",
				"import time; f=lambda x: time.sleep(x);[f(0.002) for _ in range(100_000)]",
			),
			"python",
			"function__entry",
			100 * time.Millisecond,
		},
		/*
		   TODO: this fails in CI, find out why
		   {
		       "Python (libstapsdt)",
		       exec.Command("python", "testdata/libstapsdt.py"),
		       "X",
		       "Y",
		       100 * time.Millisecond,
		   },
		*/
		{
			"C (simple)",
			exec.Command("testdata/simple.o"),
			"X",
			"Y",
			0,
		},
		{
			"C (semaphore)",
			exec.Command("testdata/semaphore.o"),
			"X",
			"Y",
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, p := newMapProg(t)

			// Run the tracee in the background.
			if err := tt.cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := tt.cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			}()

			// Give some time for the process to start/setup the probes.
			time.Sleep(tt.sleep)

			// Open and attach the USDT probe.
			u, err := usdt.New(p, tt.provider, tt.probe, tt.cmd.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}

			// Wait for the probe to fire.
			time.Sleep(5 * time.Millisecond)

			// Assert that the value at index 0 has been updated to 1.
			assertMapValue(t, m, 0, 1)

			if err := u.Close(); err != nil {
				t.Fatal(err)
			}

			// Reset map value to 0 at index 0.
			if err := m.Update(uint32(0), uint32(0), ebpf.UpdateExist); err != nil {
				t.Fatal(err)
			}

			// Wait for the probe to eventually fire.
			time.Sleep(5 * time.Millisecond)

			// Assert that this time the value has not been updated.
			assertMapValue(t, m, 0, 0)
		})
	}
}

func newMapProg(t *testing.T) (*ebpf.Map, *ebpf.Program) {
	// Create ebpf map. Will contain only one key with initial value 0.
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create ebpf program. When called, will set the value of key 0 in
	// the map created above to 1.
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			// u32 key = 0
			asm.Mov.Imm(asm.R1, 0),
			asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),

			// u32 val = 1
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreMem(asm.RFP, -8, asm.R1, asm.Word),

			// bpf_map_update_elem(...)
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -8),
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnMapUpdateElem.Call(),

			// exit 0
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Dual MIT/GPL",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Close the program and map on test teardown.
	t.Cleanup(func() {
		m.Close()
		p.Close()
	})

	return m, p
}

func assertMapValue(t *testing.T, m *ebpf.Map, k, v uint32) {
	var val uint32
	if err := m.Lookup(k, &val); err != nil {
		t.Fatal(err)
	}
	if val != v {
		t.Fatalf("unexpected value: want '%d', got '%d'", v, val)
	}
}
