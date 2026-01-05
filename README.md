# Transparent Redirection to Envoy Proxy using eBPF and SO_ORIGINAL_DST 

An experimental integration of eBPF with Envoy proxy for transparent traffic redirection using `SO_ORIGINAL_DST` to derive the original destination, rather than relying in hardcoded backends.

## Overview

This program leverages eBPF programs attached to the Linux kernel to transparently proxy traffic to Envoy as well as altering SO_ORIGINAL_DST (actually `getsockopt` syscall) to derive original destination, the client tried to connect to.

In this setup, we:
- Perform transparent Redirection to Envoy Proxy using eBPF TC program
- Run Envoy Proxy that listens on port 8080
- Alter SO_ORIGINAL_DST (actually `getsockopt` syscall) to derive original destination, the client tried to connect to.

## Running

Start Envoy:
```sh
sudo envoy -c envoy.yaml
```

And in another terminal a HTTP server:
```sh
python3 -m http.server 8000
```

Build and run the tproxy:
```sh
go generate
go build
sudo ./tproxy -i <interface> -ports 8000
```
**NOTE**: eBPF program is configured to only redirect requests to port 8000 so we don't mess up with the rest of the network traffic.

Curl the server through the interface where you have attached eBPF TC programs and observe how the Envoy transparently captures/observes and proxies the traffic.
