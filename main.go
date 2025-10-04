package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf tproxy ebpf/tproxy.c

import (
	"os"
	"log"
	"fmt"
	"flag"
	"context"
	"os/signal"
	"syscall"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/oraoto/go-pidfd"
)

// Utility function to load the key:value into the echo_ports BPF map
func insertEchoPort(key uint32, value uint64, echoPorts *ebpf.Map) error {
	if err := echoPorts.Put(&key, &value); err != nil {
		return err
	}
	return nil
}

func main() {
	targetPid := flag.Int("pid", 0, "Target process PID")
	targetFd := flag.Int("fd", 0, "Target file descriptor")
	flag.Parse()

	if *targetPid == 0 || *targetFd == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s -pid <PID> -fd <FD>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	log.Printf("Target PID: %d\n", *targetPid)
	log.Printf("Target FD: %d\n", *targetFd)

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Print("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel 
	var objs tproxyObjects
	if err := loadTproxyObjects(&objs, nil); err != nil {
		log.Print("Error loading eBPF objects:", err)
	}
	defer objs.Close()

	// Get current process network namespace, because we need to attach the eBPF program to it
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Fatal("Failed to read netns:", err)
	}
	defer netns.Close()

	// Attach the eBPF program to the network namespace
	// NOTE: Multiple programs can be attached to one network namespace. Programs will be invoked in the same order as they were attached.
	// Incoming traffic to already established connections is delivered as usual without triggering the BPF sk_lookup hook.
	l, err := link.AttachNetNs(int(netns.Fd()), objs.EchoDispatch)
	if err != nil {
		log.Fatal("Failed to attach eBPF program to the network namespace:", err)
	}
	defer l.Close()

	/* NOTE: Unix-like systems traditionally represent objects as files, but processes have always been an exception. 
	They are, instead, represented by process IDs (integer PID). There are a few problems with this representation.
	The biggest one is that PIDs are reused and this can happen quickly, which creates a race condition 
	where code that operates on a process might end up performing an action 
	on the wrong process (in case the same PID of the proccess that got shutdown just got reused).
	For this demo, we are not taking this into an account.*/

	// Get the file descriptor to a process 
	// Remember that each process has it's own file descriptor table
	targetPidFd, err := pidfd.Open(*targetPid, 0)
	if err != nil {
		panic(err)
	}

	// Duplicate socket FD
	sockFd, err := targetPidFd.GetFd(*targetFd, 0)
	if err != nil {
		panic(err)
	}

	// Store the socket file descriptor to the echo_socket eBPF map
	var key uint32 = 0
	var val uint64 = uint64(sockFd)
	if err := objs.EchoSocket.Put(&key, &val); err != nil {
		panic(err)
	}

	// Now add some random port on which the packets will be redirected to choosen socket
	insertEchoPort(uint32(8081), uint64(0), objs.EchoPorts)
	insertEchoPort(uint32(8082), uint64(0), objs.EchoPorts)
	insertEchoPort(uint32(8083), uint64(0), objs.EchoPorts)

	log.Printf("Running eBPF programs...")

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	<-ctx.Done()
	log.Println("Received signal, exiting...")
}
