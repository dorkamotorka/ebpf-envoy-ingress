# ebpf-envoy

An experimental integration of eBPF with Envoy proxy for transparent traffic redirection at the socket level.

## Overview

`ebpf-envoy` leverages eBPF programs attached to the Linux kernel to transparently proxy traffic to Envoy. The eBPF program intercepts incoming connections and redirects selected ports directly to an Envoy socket, enabling flexible networking scenarios such as transparent proxying, load balancing, or advanced filtering.

- **Proxy with eBPF:** Uses a custom eBPF `sk_lookup` program (`ebpf/tproxy.c`) to redirect traffic based on destination port and process ID.
- **Envoy Integration:** Envoy configuration (`envoy.yaml`) defines listeners, routes, and clusters, including blocking specific endpoints and routing others to echo services.
- **Go-based CLI:** The Go program (`main.go`) orchestrates eBPF loading, socket mapping, and process selection.

## Features

- Transparent TCP socket redirection via eBPF
- Prevents proxy from proxying itself for safety
- Flexible Envoy routing and filtering (block, allow, custom response)
- Docker Compose setup for easy local testing

## Getting Started

### Prerequisites

- **Linux Kernel 6.10+** is required for `bpf_get_current_pid_tgid()` in the `sk_lookup` eBPF program type.
- Go 1.23+ for building the CLI.
- Docker for running Envoy and echo services.

### Building

```sh
go generate
go build
```

### Running

1. Start Envoy:

   ```sh
   sudo envoy -c envoy.yaml
   ```
   and in another terminal a HTTP server:
   ```sh
   sudo python3 -m http.server 80
   ```
   **NOTE**: eBPF program is configured to only redirect requests to port 80 so we don't mess up with the rest of the network traffic.

2. Find the PID and FD of the Envoy process/socket:

   ```sh
   sudo ss -lptn
   ```

3. Run the tproxy CLI, specifying the Envoy's PID and FD:

   ```sh
   sudo ./tproxy -pid <PID> -fd <FD>
   ```

4. Curl echo server and observe how the Envoy transparently captures/observes and proxies the traffic:
   ```sh
   curl http://127.0.0.1:80
   ```

### Configuration

- **Envoy:** See [`envoy.yaml`](https://github.com/dorkamotorka/ebpf-envoy/blob/main/envoy.yaml) for listener, route, and cluster setup.
- **Docker Compose:** See [`docker-compose.yaml`](https://github.com/dorkamotorka/ebpf-envoy/blob/main/docker-compose.yaml) for multi-service orchestration.

## Architecture

- **eBPF program:** Located at [`ebpf/tproxy.c`](https://github.com/dorkamotorka/ebpf-envoy/blob/main/ebpf/tproxy.c), defines maps for ports, sockets, and PIDs, and the redirection logic.
- **Go CLI:** [`main.go`](https://github.com/dorkamotorka/ebpf-envoy/blob/main/main.go) loads eBPF objects, manages PID/fd handling, and attaches programs.
- **Envoy Proxy:** Configured to block certain endpoints and route traffic to echo services.

## License

Apache License 2.0. See [`LICENSE`](https://github.com/dorkamotorka/ebpf-envoy/blob/main/LICENSE) for details.

---

> _Note: Code search results may be incomplete. For full source and documentation, visit the [GitHub repository](https://github.com/dorkamotorka/ebpf-envoy)._
