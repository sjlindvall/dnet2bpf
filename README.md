# dnet2-bpf

Initial Linux DNET2 data-plane prototype for Ubuntu 22.04 and 24.04. It attaches
an XDP pass-through counter to two interfaces and a TC egress classifier that
clones outbound frames bidirectionally between them. It is not yet a complete
DNET2 implementation: RX duplicate suppression, multicast filtering and protocol
sequence parsing are intentionally deferred.

## Safety model

- XDP always returns `XDP_PASS`; this release never drops RX traffic.
- Existing XDP programs are not replaced.
- A temporary skb mark prevents clone recursion; the original mark is restored.
- Only TC filters with DNET2's handle/priority are detached.
- An existing `clsact` qdisc is preserved. A qdisc created by this daemon is
  removed at shutdown.
- SIGINT/SIGTERM performs detach and cleanup. A crash can leave attachments;
  recovery commands are below.
- Never configure the management/SSH NIC as A or B.

## Prerequisites

Ubuntu 24.04:

```sh
sudo apt update
sudo apt install build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
  pkg-config linux-headers-$(uname -r) linux-tools-$(uname -r) \
  linux-tools-common iproute2 ethtool tcpdump
```

Ubuntu 22.04 uses the same package list. `bpftool` comes from the matching
`linux-tools-$(uname -r)` package. The code uses APIs present in libbpf 0.5 and
1.3 and conservative BPF features suitable for Linux 5.15.

## Build and local test

```sh
make
make check
sudo ./build/dnet2d -r build/dnet2_rx.bpf.o -t build/dnet2_tx.bpf.o ens19 ens20
```

Stop with Ctrl-C. Inspect attachments and traffic in other terminals:

```sh
ip -details link show dev ens19
sudo tc filter show dev ens19 egress
sudo tcpdump -eni ens19
sudo tcpdump -eni ens20
```

The loader selects generic/SKB XDP for broad compatibility with emulated e1000
and older drivers. A later release can add an explicit native-XDP option for the
physical Intel I350/igb target.

## Install

```sh
sudo make install
sudo editor /etc/dnet2/dnet2.conf
sudo systemctl daemon-reload
sudo systemctl enable --now dnet2
systemctl status dnet2
journalctl -u dnet2 -f
```

The default configuration is `ens19`/`ens20`; change it before starting the
service on a machine with different interface names.

## Uninstall

```sh
sudo systemctl disable --now dnet2
sudo make uninstall
sudo systemctl daemon-reload
```

Uninstall deliberately retains `/etc/dnet2/dnet2.conf`.

## Crash recovery

First verify the targets. These commands remove XDP and the DNET2 TC filters:

```sh
sudo ip link set dev ens19 xdpgeneric off
sudo ip link set dev ens20 xdpgeneric off
sudo tc filter del dev ens19 egress protocol all pref 1 handle 1 bpf
sudo tc filter del dev ens20 egress protocol all pref 1 handle 1 bpf
```

Do not delete `clsact` blindly because another application may use it. Inspect
with `tc filter show dev INTERFACE ingress` and `egress` first.

## Current behavior and next work

Every egress frame is cloned, including ARP, IPv6 and management protocols on A/B.
This is intentional for architecture validation but too broad for production.
The next phase should add configured EtherType/IP/UDP/multicast filters, shared or
pinned statistics, RX duplicate keys with expiry, and native-XDP selection.
