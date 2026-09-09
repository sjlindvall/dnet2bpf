# dnet2-bpf

Linux DNET2 data-plane prototype for Ubuntu 22.04 and 24.04. The optional TAP
mode exposes a normal Linux IPv4 adapter over two redundant LANs. Legacy mode attaches
an XDP pass-through counter to two interfaces and a TC egress classifier that
clones outbound frames bidirectionally between them. It is not yet a complete
DNET2 implementation: RX duplicate suppression, multicast filtering and protocol
sequence parsing are intentionally deferred.

## Virtual adapter: 172.23.0.0/16 over networks A and B

The installed service now defaults to a nonpersistent TAP named `dnet2` with
address **172.23.1.1/16**. A remains on 172.21.* and B on 172.22.*; their
addresses and routes are not changed. Choose a unique virtual address per host.
For a development run:

```sh
sudo ./build/dnet2d -v dnet2 ens19 ens20
# Another host / startup address:
sudo ./build/dnet2d -v dnet2 -a 172.23.1.2/16 ens19 ens20
```

While the daemon runs, configure the adapter like other Linux interfaces:

```sh
ip addr show dev dnet2
sudo ip addr replace 172.23.1.1/16 dev dnet2
# To change address, remove the old address before adding the new one:
sudo ip addr del 172.23.1.1/16 dev dnet2
sudo ip addr add 172.23.1.2/16 dev dnet2
sudo ip link set dev dnet2 mtu 1400
```

For persistent startup settings, edit `DNET2_VIRTUAL_OPTIONS` in
`/etc/dnet2/dnet2.conf`, e.g. `"-v dnet2 -a 172.23.1.2/16"`, then restart the
service. Existing configurations are preserved on install: add this setting to
opt in. An empty value (or omitting `-v` and `-a` on the command line) retains
legacy BPF mode. TAP mode does not attach BPF programs; stop an old daemon and
remove any stale legacy attachments before switching modes.

Applications use the connected 172.23.0.0/16 route through `dnet2`. Outbound
IPv4 frames with a 172.23.* source and ARP requests/replies targeting 172.23.*
are sent unchanged on both A and B, including the TAP's Ethernet source address.
Incoming overlay frames addressed to the TAP, broadcast or multicast are
injected into it. The transport filter remains 172.23.0.0/16 even when the TAP
address is changed using normal Linux tools. There is no NAT or IP encapsulation.
IPv6 and VLAN-tagged frames are not transported; use VLAN subinterfaces for A/B
if needed. Both physical links must already be up. MTU starts at the smaller
physical MTU, capped at 1500; keep it within both physical links' limits.

TAP mode needs `/dev/net/tun`, CAP_NET_ADMIN and CAP_NET_RAW. The TAP disappears
when the daemon exits, including on a crash. Existing interfaces are never
adopted. Packet sockets temporarily request promiscuous reception on A/B so
frames for the TAP MAC are received; switches/hypervisors must permit that MAC.
Linux ARP behavior can also answer for local addresses on other interfaces;
when necessary configure `arp_ignore=1` on A/B through your normal sysctl setup.

This matches the described IPv4 topology, but Windows DNET2 wire compatibility
has not been verified. No DNET2 sequence headers or RX duplicate suppression are
implemented: packets received on both LANs can be delivered twice, including UDP.
Validate with captures from the Windows host before production use:

```sh
sudo tcpdump -eni ens19 'arp or net 172.23.0.0/16'
sudo tcpdump -eni ens20 'arp or net 172.23.0.0/16'
ping -I dnet2 172.23.1.2
```

## Legacy BPF safety model

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

## Legacy BPF behavior and next work

Every egress frame is cloned, including ARP, IPv6 and management protocols on A/B.
This is intentional for architecture validation but too broad for production.
The next phase should add configured EtherType/IP/UDP/multicast filters, shared or
pinned statistics, RX duplicate keys with expiry, and native-XDP selection.
