/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#pragma once

#include "map_defs.h"

struct lb_egress_key {
	__be32 src_ip;
};

struct lb_egress_val {
	__be32 lb_ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lb_egress_key);
	__type(value, struct lb_egress_val);
	__uint(max_entries, 65536);
	__uint(map_flags, LRU_MEM_FLAVOR);
} lb_egress_map SEC(".maps");

static __always_inline int
lb_egress_apply_v4(struct __ctx_buff *ctx __maybe_unused, struct iphdr *ip4)
{
	struct lb_egress_key key = {};
	struct lb_egress_val *val;
	__be32 old_saddr;

	key.src_ip = ip4->saddr;

	val = map_lookup_elem(&lb_egress_map, &key);
	if (!val)
		return CTX_ACT_OK;

	old_saddr = ip4->saddr;
	ip4->saddr = val->lb_ip;

	csum_replace4(&ip4->check, old_saddr, val->lb_ip);

	return CTX_ACT_OK;
}