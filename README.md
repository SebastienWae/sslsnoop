# sslsnoop

`sslsnoop` is a program that intercepts SSL content using eBPF to trace SSL libraries. It can be used to monitor SSL traffic of a specific process or all processes on the system.

## Features
- [x] Support OpenSSL
- [ ] Support GNUTLS
- [ ] Handle statically linked libraries
- [ ] Filter by PID
- [ ] Filter by process name

## How It Works
Using eBPF `uprobes`, `sslsnoop` can intercept SSL content before it is encrypted and sent or after it is received and decrypted. For example by attaching to the `SSL_write` function of `OpenSSL`, `sslsnoop` can access data before it is encrypted and sent.

## Setup and Usage
### Prerequisites
- [rust](https://www.rust-lang.org/)
- [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)
- [bpftool](https://github.com/libbpf/bpftool)
- [clang](https://clang.llvm.org/)

### Installation
```bash
git clone https://github.com/sebastienwae/sslsnoop.git
cd sslsnoop
cargo build --release
```

### Usage
```bash
sudo ./target/release/sslsnoop
```
