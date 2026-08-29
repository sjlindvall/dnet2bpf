#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "dnet2_shared.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dnet2_config);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DNET2_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

SEC("xdp")
int dnet2_rx(struct xdp_md *ctx)
{
	__u32 zero = 0, stat;
	struct dnet2_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
	__u64 *counter;

	if (!cfg || !cfg->enabled)
		return XDP_PASS;
	if (ctx->ingress_ifindex == cfg->ifindex_a)
		stat = DNET2_RX_A;
	else if (ctx->ingress_ifindex == cfg->ifindex_b)
		stat = DNET2_RX_B;
	else
		return XDP_PASS;
	counter = bpf_map_lookup_elem(&stats_map, &stat);
	if (counter)
		__sync_fetch_and_add(counter, 1);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
