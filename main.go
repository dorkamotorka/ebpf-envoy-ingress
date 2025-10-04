package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf tproxy ebpf/tproxy.c

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/oraoto/go-pidfd"
)

// htons converts a host-order TCP/UDP port to network byte order.
// SK_LOOKUP receives ctx->local_port in network order, so userspace
// must insert keys the same way.
func htons(p uint16) uint16 { return (p<<8)&0xff00 | p>>8 }

// insertEchoPort loads key:value into the echo_ports BPF map.
func insertEchoPort(key uint32, value uint64, echoPorts *ebpf.Map) error {
	return echoPorts.Put(&key, &value)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("tproxy: ")

	targetPid := flag.Int("pid", 0, "Target process PID (the process that owns the listening socket)")
	targetFd := flag.Int("fd", 0, "Target file descriptor (the listening socket FD in that process)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s -pid <PID> -fd <FD>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *targetPid == 0 || *targetFd == 0 {
		flag.Usage()
		os.Exit(2)
	}

	log.Printf("starting (pid=%d, fd=%d)", *targetPid, *targetFd)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("warn: removing memlock rlimit: %v", err)
	}

	var objs tproxyObjects
	if err := loadTproxyObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()
	log.Printf("eBPF objects loaded")

	// Attach SK_LOOKUP program to the current netns
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Fatalf("open self netns: %v", err)
	}
	defer netns.Close()

	l, err := link.AttachNetNs(int(netns.Fd()), objs.Redirect)
	if err != nil {
		log.Fatalf("attach SK_LOOKUP to netns(fd=%d): %v", netns.Fd(), err)
	}
	defer l.Close()
	log.Printf("attached SK_LOOKUP program to current netns (fd=%d)", netns.Fd())

	// Acquire a pidfd for the target process and duplicate its socket FD
	// Using pidfd avoids PID-reuse races when referring to a specific process.
	pfd, err := pidfd.Open(*targetPid, 0)
	if err != nil {
		log.Fatalf("pidfd open pid=%d: %v", *targetPid, err)
	}

	sockFd, err := pfd.GetFd(*targetFd, 0)
	if err != nil {
		log.Fatalf("pidfd getfd pid=%d, fd=%d: %v", *targetPid, *targetFd, err)
	}
	log.Printf("duplicated target socket (pid=%d fd=%d -> newfd=%d)", *targetPid, *targetFd, sockFd)

	// Publish the socket FD into the echo_socket map
	// The BPF program will bpf_sk_assign() to this socket.
	{
		var k uint32 = 0
		v := uint64(sockFd)
		if err := objs.EchoSocket.Put(&k, &v); err != nil {
			log.Fatalf("echo_socket[0]=%d put: %v", sockFd, err)
		}
		log.Printf("echo_socket map populated (key=%d, fd=%d)", k, sockFd)
	}

	// Configure which destination ports should be redirected
	// Note: ctx->local_port is network-order; insert keys as htons(port).
	for _, p := range []uint16{8081, 8082, 8083} {
		k := uint32(htons(p))
		if err := insertEchoPort(k, 0, objs.EchoPorts); err != nil {
			log.Fatalf("echo_ports[%d] put: %v", p, err)
		}
	}

	log.Printf("Program running — press Ctrl+C to exit")
	<-ctx.Done()
	log.Printf("signal received, shutting down")
}
