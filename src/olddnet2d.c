#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "dnet2_shared.h"

static volatile sig_atomic_t exiting;
static int ifa, ifb;
static __u32 xdp_id_a, xdp_id_b;
static bool tc_a_created, tc_b_created, tc_a_attached, tc_b_attached;
static struct bpf_object *rx_obj, *tx_obj;

static void on_signal(int signo) { (void)signo; exiting = 1; }

static int update_maps(struct bpf_object *obj, const struct dnet2_config *cfg)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, "config_map");
	__u32 key = 0;
	if (!map) return -ENOENT;
	return bpf_map_update_elem(bpf_map__fd(map), &key, cfg, BPF_ANY);
}

static int open_load(const char *path, struct bpf_object **obj)
{
	*obj = bpf_object__open_file(path, NULL);
	if (libbpf_get_error(*obj)) {
		int err = (int)libbpf_get_error(*obj);
		*obj = NULL;
		return err;
	}
	return bpf_object__load(*obj);
}

static int attach_tc(int ifindex, int prog_fd, bool *created, bool *attached)
{
	struct bpf_tc_hook hook = { .sz = sizeof(hook), .ifindex = ifindex,
		.attach_point = BPF_TC_EGRESS };
	struct bpf_tc_opts opts = { .sz = sizeof(opts), .prog_fd = prog_fd,
		.handle = 1, .priority = 1 };
	int err = bpf_tc_hook_create(&hook);
	if (!err) *created = true;
	else if (err != -EEXIST) return err;
	err = bpf_tc_attach(&hook, &opts);
	if (!err) *attached = true;
	return err;
}

static void detach_tc(int ifindex, bool created, bool attached)
{
	struct bpf_tc_hook hook = { .sz = sizeof(hook), .ifindex = ifindex,
		.attach_point = BPF_TC_EGRESS };
	struct bpf_tc_opts opts = { .sz = sizeof(opts), .handle = 1, .priority = 1 };
	if (attached) bpf_tc_detach(&hook, &opts);
	/* Destroy clsact only when this process created it; preserve existing qdiscs. */
	if (created) { hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS; bpf_tc_hook_destroy(&hook); }
}

static void cleanup(void)
{
	__u32 current = 0;
	/* Detach only if the program we installed is still current. */
	if (ifa && xdp_id_a && !bpf_get_link_xdp_id(ifa, &current, XDP_FLAGS_SKB_MODE) &&
	    current == xdp_id_a)
		bpf_set_link_xdp_fd(ifa, -1, XDP_FLAGS_SKB_MODE);
	current = 0;
	if (ifb && xdp_id_b && !bpf_get_link_xdp_id(ifb, &current, XDP_FLAGS_SKB_MODE) &&
	    current == xdp_id_b)
		bpf_set_link_xdp_fd(ifb, -1, XDP_FLAGS_SKB_MODE);
	detach_tc(ifa, tc_a_created, tc_a_attached);
	detach_tc(ifb, tc_b_created, tc_b_attached);
	bpf_object__close(tx_obj);
	bpf_object__close(rx_obj);
}

static void print_stats(void)
{
	static const char *names[DNET2_STAT_MAX] = { "rx-a", "rx-b", "tx-a", "tx-b",
		"clone-a-b", "clone-b-a", "clone-errors", "marked-skips" };
	struct bpf_map *rx_map = bpf_object__find_map_by_name(rx_obj, "stats_map");
	struct bpf_map *tx_map = bpf_object__find_map_by_name(tx_obj, "stats_map");
	int rx_fd = rx_map ? bpf_map__fd(rx_map) : -1;
	int tx_fd = tx_map ? bpf_map__fd(tx_map) : -1;
	__u32 i; __u64 value;
	if (rx_fd < 0 || tx_fd < 0) return;
	for (i = 0; i < DNET2_STAT_MAX; i++) {
		int fd = i <= DNET2_RX_B ? rx_fd : tx_fd;
		if (!bpf_map_lookup_elem(fd, &i, &value))
			printf("%s=%llu%s", names[i], (unsigned long long)value,
			       i + 1 == DNET2_STAT_MAX ? "\n" : " ");
	}
	fflush(stdout);
}

static void usage(const char *p)
{
	fprintf(stderr, "Usage: %s [-r rx-object] [-t tx-object] IFACE_A IFACE_B\n", p);
}

int main(int argc, char **argv)
{
	const char *rx_path = "/usr/local/lib/dnet2-bpf/dnet2_rx.bpf.o";
	const char *tx_path = "/usr/local/lib/dnet2-bpf/dnet2_tx.bpf.o";
	struct bpf_program *rx_prog, *tx_prog;
	struct dnet2_config cfg = {};
	int opt, err, rx_fd, tx_fd;

	while ((opt = getopt(argc, argv, "r:t:h")) != -1) {
		if (opt == 'r') rx_path = optarg;
		else if (opt == 't') tx_path = optarg;
		else { usage(argv[0]); return opt == 'h' ? 0 : 2; }
	}
	if (argc - optind != 2) { usage(argv[0]); return 2; }
	ifa = if_nametoindex(argv[optind]); ifb = if_nametoindex(argv[optind + 1]);
	if (!ifa || !ifb || ifa == ifb) { fprintf(stderr, "Invalid or identical interfaces\n"); return 2; }
	cfg.ifindex_a = ifa; cfg.ifindex_b = ifb; cfg.enabled = 1;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if ((err = open_load(rx_path, &rx_obj)) || (err = open_load(tx_path, &tx_obj))) {
		fprintf(stderr, "BPF load failed: %s\n", strerror(-err)); goto fail;
	}
	if ((err = update_maps(rx_obj, &cfg)) || (err = update_maps(tx_obj, &cfg))) goto fail;
	rx_prog = bpf_object__find_program_by_name(rx_obj, "dnet2_rx");
	tx_prog = bpf_object__find_program_by_name(tx_obj, "dnet2_tx");
	if (!rx_prog || !tx_prog) { err = -ENOENT; goto fail; }
	rx_fd = bpf_program__fd(rx_prog); tx_fd = bpf_program__fd(tx_prog);

	/* Refuse to replace existing XDP programs. Generic mode maximizes VM/5.15 compatibility. */
	err = bpf_set_link_xdp_fd(ifa, rx_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
	if (err) goto fail;
	err = bpf_get_link_xdp_id(ifa, &xdp_id_a, XDP_FLAGS_SKB_MODE);
	if (err || !xdp_id_a) { if (!err) err = -ENOENT; goto fail; }
	err = bpf_set_link_xdp_fd(ifb, rx_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
	if (err) goto fail;
	err = bpf_get_link_xdp_id(ifb, &xdp_id_b, XDP_FLAGS_SKB_MODE);
	if (err || !xdp_id_b) { if (!err) err = -ENOENT; goto fail; }
	if ((err = attach_tc(ifa, tx_fd, &tc_a_created, &tc_a_attached)) ||
	    (err = attach_tc(ifb, tx_fd, &tc_b_created, &tc_b_attached))) goto fail;

	signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
	printf("dnet2d active: %s(%d) <-> %s(%d)\n", argv[optind], ifa, argv[optind + 1], ifb);
	while (!exiting) { print_stats(); sleep(2); }
	cleanup();
	return 0;
fail:
	fprintf(stderr, "dnet2d: %s\n", strerror(-err)); cleanup(); return 1;
}
