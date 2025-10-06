package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf tproxy ebpf/tproxy.c

import (
	"os"
	"log"
	"flag"
	"context"
	"os/signal"
	"syscall"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/oraoto/go-pidfd"
)

// insertEchoPort stores a (port -> value) entry into the EchoPorts eBPF map.
// Example:
// * key: TCP destination port to match
// * value: currently unused (set to 0) but reserved for future metadata
func insertEchoPort(key uint32, value uint64, echoPorts *ebpf.Map) error {
	if err := echoPorts.Put(&key, &value); err != nil {
		return err
	}
	return nil
}

func main() {
	// CLI parameters:
	//   -pid: PID of the process that owns the target socket
	//   -fd : File descriptor number of the socket in that process' FD table
	targetPid := flag.Int("pid", 0, "Target process PID")
	targetFd := flag.Int("fd", 0, "Target file descriptor")
	flag.Parse()

	if *targetPid == 0 || *targetFd == 0 {
    		flag.PrintDefaults()
		log.Fatalf("Usage: %s -pid <PID> -fd <FD>", os.Args[0])
	}

	// Using pidfd avoids PID-reuse races when referring to a specific process.
	targetPidFd, err := pidfd.Open(*targetPid, 0)
	if err != nil {
		log.Fatalf("Cannot open process %d: %v", *targetPid, err)
	}

	sockFd, err := targetPidFd.GetFd(*targetFd, 0)
	if err != nil {
		log.Fatalf("Cannot duplicate fd %d from process %d: %v", *targetFd, *targetPid, err)
	}

	// Set up cancellation on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Allow locked memory for eBPF maps/programs on kernels < 5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("memlock: failed to lift RLIMIT_MEMLOCK: %v", err)
	}

	// Load compiled eBPF objects (programs + maps) into the kernel.
	var objs tproxyObjects
	if err := loadTproxyObjects(&objs, nil); err != nil {
		log.Printf("ebpf: load objects failed: %v", err)
	}
	defer objs.Close()

	// Open our current network namespace; the eBPF program will attach to it.
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Fatalf("netns: open /proc/self/ns/net failed: %v", err)
	}
	defer netns.Close()


	var pid uint32 = uint32(*targetPid)
	var value uint32 = 0
	if err := objs.tproxyMaps.PidMap.Update(&pid, &value, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update pid_map (pid %d): %v", pid, err)
	}

	// Attach the eBPF sk_lookup program to the namespace.
	// Multiple programs can be attached; they run in the order attached.
	// Established connections won't trigger sk_lookup.
	l, err := link.AttachNetNs(int(netns.Fd()), objs.Redirect)
	if err != nil {
		log.Fatalf("link: attach to current netns failed: %v", err)
	}
	defer l.Close()

	// Store the duplicated socket FD into the EchoSocket BPF map (key=0).
	var key uint32 = 0
	var val uint64 = uint64(sockFd)
	if err := objs.EchoSocket.Put(&key, &val); err != nil {
		log.Fatalf("Failed to update Echo Socket eBPF map: %v", err)
	}

	// Register ports that should be redirected to the chosen socket.
	// Values are placeholders (0) for now.
	if err := insertEchoPort(uint32(80), uint64(1), objs.EchoPorts); err != nil {
		log.Fatalf("Failed to update Echo Port eBPF map: %v", err)
	}

	log.Printf("Program running..")
	log.Printf("TProxy redirecting requests on port 80 to process with PID %d and FD %d", *targetPid, *targetFd)

	// Block until a termination signal is received.
	<-ctx.Done()
	log.Println("signal: received termination request; shutting down")
}
