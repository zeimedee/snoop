package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const bpfPath = "bpf/snoop.o"

func main() {
	spec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		log.Fatalf("failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to load spec collections: %v", err)
	}
	defer coll.Close()

	for p := range coll.Programs {
		fmt.Println(p)
	}

	prog, ok := coll.Programs["tracepoint__syscalls_sys_enter_openat"]
	if !ok {
		log.Fatalf("failed to find tracepoint__syscalls_sys_enter_openat in ELF")
	}

	l, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})

	if err != nil {
		log.Fatalf("failed to attach eBPF program: %v", err)
	}

	defer l.Close()

	fmt.Println("eBPf attached successfully.........")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Exiting and detaching.........")
}
