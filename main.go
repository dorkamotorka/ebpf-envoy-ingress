package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf tproxy ebpf/tproxy.c

import (
	"os"
	"log"
	"net"
	"flag"
	"context"
	"os/signal"
	"syscall"
	"strings"
	"strconv"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	CGROUP_PATH = "/sys/fs/cgroup" // Root cgroup path
)

var (
	ifname string
	ports string
)

func main() {
	flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF programs will be attached")
	flag.StringVar(&ports, "ports", "", "List of listening ports (separated by ',')")
	flag.Parse()

	if ports == "" {
		flag.Usage()
		os.Exit(1)
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

	// Example: backends = "80,8080"
	// Make sure it doesn't overlap with Envoy listen port
	portList := strings.Split(ports, ",")
	for _, port := range portList {
		port = strings.TrimSpace(port)
		n, err := strconv.ParseUint(port, 10, 32)
		if err != nil {
			panic(err)
		}
		if err := objs.tproxyMaps.Ports.Put(uint32(n), uint32(1)); err != nil {
			log.Fatalf("Error adding port %d to eBPF map: %v", n, err)
		}
		log.Printf("Added port %d", n)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	tcin, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcBoth,
		Attach:	   ebpf.AttachTCXIngress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching TC on Ingress:", err)
	}
	defer tcin.Close()
	tcout, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcBoth,
		Attach:	   ebpf.AttachTCXEgress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching TC on Egress:", err)
	}
	defer tcout.Close()

	s, err := link.AttachCgroup(link.CgroupOptions{
		Path:    CGROUP_PATH,
		Attach:  ebpf.AttachCGroupGetsockopt,
		Program: objs.CgGetsockopt,
	})
	if err != nil {
		log.Print("Attaching CgSockOpt program to Cgroup:", err)
	}
	defer s.Close()


	log.Printf("Program running..")
	log.Printf("TProxy redirecting requests to Envoy!")

	// Block until a termination signal is received.
	<-ctx.Done()
	log.Println("signal: received termination request; shutting down")
}
