```
sudo ss -lptn

sudo ./tproxy -pid 1757219 -fd 54 # Choose one of the FDs of the envoy proxy
```

At least 6.10 is required for `bpf_get_current_pid_tgid()` in `sk_lookup` eBPF program type.
