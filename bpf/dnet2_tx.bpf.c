#include <linux/bpf.h>
#include <linux/pkt_cls.h>
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

static __always_inline void count(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&stats_map, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
}

SEC("classifier")
int dnet2_tx(struct __sk_buff *skb)
{
	__u32 zero = 0, peer, tx_stat, clone_stat, old_mark;
	struct dnet2_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
	long rc;

	if (!cfg || !cfg->enabled)
		return TC_ACT_OK;
	if (skb->mark == DNET2_MARK) {
		count(DNET2_MARKED_SKIPS);
		return TC_ACT_OK;
	}
	if (skb->ifindex == cfg->ifindex_a) {
		peer = cfg->ifindex_b;
		tx_stat = DNET2_TX_A;
		clone_stat = DNET2_CLONE_A_TO_B;
	} else if (skb->ifindex == cfg->ifindex_b) {
		peer = cfg->ifindex_a;
		tx_stat = DNET2_TX_B;
		clone_stat = DNET2_CLONE_B_TO_A;
	} else {
		return TC_ACT_OK;
	}

	count(tx_stat);
	old_mark = skb->mark;
	skb->mark = DNET2_MARK;
	rc = bpf_clone_redirect(skb, peer, 0);
	skb->mark = old_mark;
	if (rc)
		count(DNET2_CLONE_ERRORS);
	else
		count(clone_stat);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
