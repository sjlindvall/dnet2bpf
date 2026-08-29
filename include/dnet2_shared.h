#ifndef DNET2_SHARED_H
#define DNET2_SHARED_H

#include <linux/types.h>

#define DNET2_MARK 0xD2E70001U

enum dnet2_stat_id {
	DNET2_RX_A = 0,
	DNET2_RX_B,
	DNET2_TX_A,
	DNET2_TX_B,
	DNET2_CLONE_A_TO_B,
	DNET2_CLONE_B_TO_A,
	DNET2_CLONE_ERRORS,
	DNET2_MARKED_SKIPS,
	DNET2_STAT_MAX
};

struct dnet2_config {
	__u32 ifindex_a;
	__u32 ifindex_b;
	__u32 enabled;
	__u32 reserved;
};

#endif
