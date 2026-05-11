/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#pragma once

#include "map_defs.h"
#include "csum.h"

struct lb_egress_steer_key {
	__be32 src_ip; /* pod IP */
};

struct lb_egress_steer_val {
	__be32 lb_ip;
	__be32 owner_ip; /* VIP owner node IP */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lb_egress_steer_key);
	__type(value, struct lb_egress_steer_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 65536);
	__uint(map_flags, LRU_MEM_FLAVOR);
} lb_egress_steer_map __section_maps_btf;

static __always_inline int
lb_egress_lookup_steer_v4(struct __ctx_buff *ctx, __be32 *lb_ip, __be32 *owner_ip)
{
	struct lb_egress_steer_key key = {};
	struct lb_egress_steer_val *val;
	__be32 src_ip;
	int ret;

	ret = ctx_load_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &src_ip,
		sizeof(src_ip));
	if (IS_ERR(ret))
		return ret;

	key.src_ip = src_ip;

	val = map_lookup_elem(&lb_egress_steer_map, &key);
	if (!val)
		return 0;

	*lb_ip = val->lb_ip;
	*owner_ip = val->owner_ip;

	return 1;
}

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

struct lb_egress_rev_key {
	__be32 src_ip;	 /* external target IP */
	__be32 dst_ip;	 /* LB IP */
	__be16 src_port; /* external target port */
	__be16 dst_port; /* LB source port */
	__u8 proto;
	__u8 pad[3];
};

struct lb_egress_rev_val {
	__be32 pod_ip;
	__be16 pod_port;
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lb_egress_rev_key);
	__type(value, struct lb_egress_rev_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 65536);
	__uint(map_flags, LRU_MEM_FLAVOR);
} lb_egress_rev_map __section_maps_btf;

static __always_inline int lb_egress_apply_v4(struct __ctx_buff *ctx)
{
	struct lb_egress_rev_key rev_key = {};
	struct lb_egress_rev_val rev_val = {};
	struct lb_egress_key key = {};
	struct lb_egress_val *val;
	struct csum_offset csum = {};
	__be32 old_saddr;
	__be32 new_saddr;
	__be32 dst_ip;
	__be16 src_port = 0;
	__be16 dst_port = 0;
	__u8 vihl;
	__u8 protocol;
	bool has_l4_ports = false;
	int l4_off;
	int ihl;
	int ret;

	ret = ctx_load_bytes(ctx, ETH_HLEN, &vihl, sizeof(vihl));
	if (IS_ERR(ret))
		return ret;

	ret = ctx_load_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, protocol), &protocol,
		sizeof(protocol));
	if (IS_ERR(ret))
		return ret;

	ret = ctx_load_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &old_saddr,
		sizeof(old_saddr));
	if (IS_ERR(ret))
		return ret;

	ret = ctx_load_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &dst_ip,
		sizeof(dst_ip));
	if (IS_ERR(ret))
		return ret;

	ihl = (vihl & 0x0f) * 4;
	l4_off = ETH_HLEN + ihl;

	key.src_ip = old_saddr;

	val = map_lookup_elem(&lb_egress_map, &key);
	if (!val)
		return 0;

	new_saddr = val->lb_ip;

	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		ret = ctx_load_bytes(ctx, l4_off, &src_port, sizeof(src_port));
		if (IS_ERR(ret))
			return ret;

		ret = ctx_load_bytes(
			ctx, l4_off + sizeof(src_port), &dst_port,
			sizeof(dst_port));
		if (IS_ERR(ret))
			return ret;

		has_l4_ports = true;
		break;
	default:
		break;
	}

	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		csum_l4_offset_and_flags(protocol, &csum);

		ret = csum_l4_replace(
			ctx, l4_off, &csum, old_saddr, new_saddr,
			BPF_F_PSEUDO_HDR | sizeof(new_saddr));
		if (IS_ERR(ret))
			return ret;
		break;
	case IPPROTO_SCTP:
		/*
		 * SCTP uses CRC32c, not the TCP/UDP checksum helper.
		 * Do not support SCTP for this MVP.
		 */
		return CTX_ACT_OK;
	default:
		break;
	}

	ret = l3_csum_replace(
		ctx, ETH_HLEN + offsetof(struct iphdr, check), old_saddr,
		new_saddr, sizeof(new_saddr));
	if (IS_ERR(ret))
		return ret;

	ret = ctx_store_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &new_saddr,
		sizeof(new_saddr), 0);
	if (IS_ERR(ret))
		return ret;

	if (has_l4_ports) {
		rev_key.src_ip = dst_ip;
		rev_key.dst_ip = new_saddr;
		rev_key.src_port = dst_port;
		rev_key.dst_port = src_port;
		rev_key.proto = protocol;

		rev_val.pod_ip = old_saddr;
		rev_val.pod_port = src_port;

		ret = map_update_elem(
			&lb_egress_rev_map, &rev_key, &rev_val, BPF_ANY);
		if (IS_ERR(ret))
			return ret;
	}

	return 1;
}

static __always_inline int lb_egress_reverse_v4(struct __ctx_buff *ctx)
{
	struct lb_egress_rev_key key = {};
	struct lb_egress_rev_val *val;
	struct csum_offset csum = {};
	__be32 old_daddr;
	__be32 src_ip;
	__u8 vihl;
	__u8 protocol;
	__be16 src_port = 0;
	__be16 dst_port = 0;
	int ihl;
	int l4_off;
	int ret;

	ret = ctx_load_bytes(ctx, ETH_HLEN, &vihl, sizeof(vihl));
	if (IS_ERR(ret))
		return ret;

	ret = ctx_load_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, protocol), &protocol,
		sizeof(protocol));
	if (IS_ERR(ret))
		return ret;

	ret = ctx_load_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &src_ip,
		sizeof(src_ip));
	if (IS_ERR(ret))
		return ret;

	ret = ctx_load_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &old_daddr,
		sizeof(old_daddr));
	if (IS_ERR(ret))
		return ret;

	ihl = (vihl & 0x0f) * 4;
	l4_off = ETH_HLEN + ihl;

	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		ret = ctx_load_bytes(ctx, l4_off, &src_port, sizeof(src_port));
		if (IS_ERR(ret))
			return ret;

		ret = ctx_load_bytes(
			ctx, l4_off + sizeof(src_port), &dst_port,
			sizeof(dst_port));
		if (IS_ERR(ret))
			return ret;
		break;
	default:
		return CTX_ACT_OK;
	}

	key.src_ip = src_ip;
	key.dst_ip = old_daddr;
	key.src_port = src_port;
	key.dst_port = dst_port;
	key.proto = protocol;

	val = map_lookup_elem(&lb_egress_rev_map, &key);
	if (!val)
		return CTX_ACT_OK;

	csum_l4_offset_and_flags(protocol, &csum);

	ret = csum_l4_replace(
		ctx, l4_off, &csum, old_daddr, val->pod_ip,
		BPF_F_PSEUDO_HDR | sizeof(val->pod_ip));
	if (IS_ERR(ret))
		return ret;

	ret = l3_csum_replace(
		ctx, ETH_HLEN + offsetof(struct iphdr, check), old_daddr,
		val->pod_ip, sizeof(val->pod_ip));
	if (IS_ERR(ret))
		return ret;

	ret = ctx_store_bytes(
		ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &val->pod_ip,
		sizeof(val->pod_ip), 0);
	if (IS_ERR(ret))
		return ret;

	return CTX_ACT_OK;
}
