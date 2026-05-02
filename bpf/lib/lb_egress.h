/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#pragma once

#include "map_defs.h"
#include "csum.h"

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
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 65536);
	__uint(map_flags, LRU_MEM_FLAVOR);
} lb_egress_map __section_maps_btf;

static __always_inline int
lb_egress_apply_v4(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	struct lb_egress_key key = {};
	struct lb_egress_val *val;
	struct csum_offset csum = {};
	__be32 old_saddr;
	__be32 new_saddr;
	int l4_off;
	int ret;

	key.src_ip = ip4->saddr;

	val = map_lookup_elem(&lb_egress_map, &key);
	if (!val)
		return CTX_ACT_OK;

	old_saddr = ip4->saddr;
	new_saddr = val->lb_ip;
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	/*
	 * Update TCP/UDP/SCTP pseudo-header checksum before changing source IP.
	 */
	switch (ip4->protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		csum_l4_offset_and_flags(ip4->protocol, &csum);

		ret = csum_l4_replace(ctx, l4_off, &csum,
				      old_saddr, new_saddr,
				      BPF_F_PSEUDO_HDR | sizeof(new_saddr));
		if (IS_ERR(ret))
			return ret;
		break;
	default:
		break;
	}

	ret = l3_csum_replace(ctx,
			      ETH_HLEN + offsetof(struct iphdr, check),
			      old_saddr,
			      new_saddr,
			      BPF_F_HDR_FIELD_MASK);
	if (IS_ERR(ret))
		return ret;

	ret = ctx_store_bytes(ctx,
			      ETH_HLEN + offsetof(struct iphdr, saddr),
			      &new_saddr,
			      sizeof(new_saddr),
			      0);
	if (IS_ERR(ret))
		return ret;

	return CTX_ACT_OK;
}
