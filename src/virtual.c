#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "virtual.h"

/* A nonpersistent TAP is removed by the kernel on every exit, including crashes.
 * Packet sockets transmit on each physical LAN without routing or NAT. */
static int packet_socket(const char *name, int *mtu)
{
    struct ifreq req = {};
    struct sockaddr_ll addr = { .sll_family = AF_PACKET,
                               .sll_protocol = htons(ETH_P_ALL) };
    struct packet_mreq membership = { .mr_type = PACKET_MR_PROMISC };
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    htons(ETH_P_ALL));
    if (fd < 0) return -1;
    snprintf(req.ifr_name, IFNAMSIZ, "%s", name);
    if (ioctl(fd, SIOCGIFMTU, &req)) goto fail;
    *mtu = req.ifr_mtu;
    addr.sll_ifindex = if_nametoindex(name);
    membership.mr_ifindex = addr.sll_ifindex;
    if (!addr.sll_ifindex || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   &membership, sizeof(membership))) goto fail;
    return fd;
fail:
    { int saved = errno; close(fd); errno = saved; }
    return -1;
}

static bool overlay_frame(const unsigned char *p, ssize_t n,
                          unsigned int network, unsigned int mask, bool rx)
{
    unsigned int ip;
    if (n < ETH_HLEN) return false;
    if (p[12] == 0x08 && p[13] == 0x00) {
        if (n < 34 || (p[14] >> 4) != 4 || (p[14] & 15) < 5 ||
            n < 14 + (p[14] & 15) * 4) return false;
        memcpy(&ip, p + (rx ? 30 : 26), 4);
        if ((ntohl(ip) & mask) == network) return true;
        /* Broadcast/multicast from overlay peers also belongs on the TAP. */
        if (rx && (ntohl(ip) == 0xffffffffU ||
                   (ntohl(ip) & 0xf0000000U) == 0xe0000000U)) {
            memcpy(&ip, p + 26, 4);
            return (ntohl(ip) & mask) == network;
        }
    } else if (p[12] == 0x08 && p[13] == 0x06) {
        /* Ethernet/IPv4 ARP; include address-probe requests with SPA=0. */
        if (n < 42 || p[14] || p[15] != 1 || p[16] != 8 || p[17] ||
            p[18] != 6 || p[19] != 4) return false;
        memcpy(&ip, p + 38, 4);
        return (ntohl(ip) & mask) == network;
    }
    return false;
}

int dnet2_virtual_run(const char *name, const char *cidr,
                      const char *a, const char *b,
                      volatile sig_atomic_t *exiting)
{
    struct ifreq req = {};
    struct in_addr address;
    struct sockaddr_in *sin = (struct sockaddr_in *)&req.ifr_addr;
    struct pollfd fds[3] = {{ .fd = -1 }, { .fd = -1 }, { .fd = -1 }};
    unsigned char frame[65536], mac[ETH_ALEN];
    char ip[INET_ADDRSTRLEN], tail;
    unsigned int prefix, mask;
    int ctl = -1, mtu_a, mtu_b, result = -1;
    unsigned long long tx_errors = 0, rx_errors = 0;

    if (strlen(name) >= IFNAMSIZ || !*name || strchr(name, '%') ||
        sscanf(cidr, "%15[^/]/%u%c", ip, &prefix, &tail) != 2 ||
        prefix < 16 || prefix > 30 || inet_pton(AF_INET, ip, &address) != 1 ||
        (ntohl(address.s_addr) & 0xffff0000U) != 0xac170000U) {
        fprintf(stderr, "Virtual adapter requires a name and 172.23.x.y/16..30 address\n");
        return -EINVAL;
    }
    mask = 0xffffffffU << (32 - prefix);
    if ((ntohl(address.s_addr) & ~mask) == 0 ||
        (ntohl(address.s_addr) & ~mask) == ~mask) return -EINVAL;
    if (if_nametoindex(name)) return -EEXIST;
    ctl = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (ctl < 0) goto done;
    fds[0].fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fds[0].fd < 0) goto done;
    snprintf(req.ifr_name, IFNAMSIZ, "%s", name);
    req.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_TUN_EXCL;
    if (ioctl(fds[0].fd, TUNSETIFF, &req)) goto done;
    fds[1].fd = packet_socket(a, &mtu_a);
    if (fds[1].fd < 0) goto done;
    fds[2].fd = packet_socket(b, &mtu_b);
    if (fds[2].fd < 0) goto done;
    req.ifr_mtu = mtu_a < mtu_b ? mtu_a : mtu_b;
    if (req.ifr_mtu > 1500) req.ifr_mtu = 1500;
    if (ioctl(ctl, SIOCSIFMTU, &req)) goto done;
    sin->sin_family = AF_INET;
    sin->sin_addr = address;
    if (ioctl(ctl, SIOCSIFADDR, &req)) goto done;
    sin->sin_addr.s_addr = htonl(mask);
    if (ioctl(ctl, SIOCSIFNETMASK, &req)) goto done;
    sin->sin_addr.s_addr = address.s_addr | htonl(~mask);
    if (ioctl(ctl, SIOCSIFBRDADDR, &req)) goto done;
    if (ioctl(ctl, SIOCGIFHWADDR, &req)) goto done;
    memcpy(mac, req.ifr_hwaddr.sa_data, ETH_ALEN);
    if (ioctl(ctl, SIOCGIFFLAGS, &req)) goto done;
    req.ifr_flags |= IFF_UP;
    if (ioctl(ctl, SIOCSIFFLAGS, &req)) goto done;
    printf("dnet2d active: %s %s over %s + %s (IPv4/ARP, no RX deduplication)\n",
           name, cidr, a, b);
    fflush(stdout);
    for (int i = 0; i < 3; i++) fds[i].events = POLLIN;
    while (!*exiting) {
        int ready = poll(fds, 3, 1000);
        if (ready < 0) { if (errno == EINTR) continue; goto done; }
        for (int i = 0; i < 3; i++) {
            ssize_t n;
            struct sockaddr_ll from;
            socklen_t len = sizeof(from);
            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                errno = EIO; goto done;
            }
            if (!(fds[i].revents & POLLIN)) continue;
            n = i ? recvfrom(fds[i].fd, frame, sizeof(frame), 0,
                             (struct sockaddr *)&from, &len)
                  : read(fds[i].fd, frame, sizeof(frame));
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) continue;
                goto done;
            }
            if (i && from.sll_pkttype == PACKET_OUTGOING) continue;
            if (!overlay_frame(frame, n, 0xac170000U, 0xffff0000U, i != 0)) continue;
            if (i) {
                if (!(frame[0] & 1) && memcmp(frame, mac, ETH_ALEN)) continue;
                /* Do not reflect our broadcasts if the LAN loops them back. */
                if (!memcmp(frame + ETH_ALEN, mac, ETH_ALEN)) continue;
                if (write(fds[0].fd, frame, n) != n) rx_errors++;
            } else {
                for (int j = 1; j < 3; j++)
                    if (send(fds[j].fd, frame, n, 0) != n) tx_errors++;
            }
        }
    }
    result = 0;
done:
    if (result) result = -errno;
    for (int i = 0; i < 3; i++) if (fds[i].fd >= 0) close(fds[i].fd);
    if (ctl >= 0) close(ctl);
    if (tx_errors || rx_errors)
        fprintf(stderr, "Virtual adapter drops: tx=%llu rx=%llu\n", tx_errors, rx_errors);
    return result;
}
