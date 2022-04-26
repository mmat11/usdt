//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mmat11/usdt"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type event bpf ./bpf/py_builtin.c

func main() {
	pid := flag.Int("pid", 0, "Pid of the process.")
	flag.Parse()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	// Open Executable on the tracee PID.
	u, err := usdt.New(objs.Handler, "python", "function__entry", *pid)
	if err != nil {
		log.Fatalf("open usdt: %v", err)
	}
	defer u.Close()

	// Open a ringbuf reader.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal.
	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("close ringbuf reader: %v", err)
		}
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("read from reader: %v", err)
			continue
		}

		// Parse the ringbuf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parse ringbuf event: %v", err)
			continue
		}

		fmt.Printf("%s:%d -> %s()\n", event.Filename, event.Lineno, event.FnName)
	}
}
