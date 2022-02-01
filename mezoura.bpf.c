#define KBUILD_MODNAME "mezoura"
#include <linux/version.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "mezoura.bpf.h"

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
	((void)__sync_fetch_and_add(ptr, val))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 150);
	__uint(pinning, 1);
	__type(key, u32);
	__type(value, struct val);
} v4_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 150);
	__uint(pinning, 1);
	__type(key, __u32[4]);
	__type(value, struct val);
} v6_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16);
	__uint(pinning, 1);
	__type(key, struct key_4);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} valid_v4 SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16);
	__uint(pinning, 1);
	__type(key, struct key_6);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} valid_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16);
	__uint(pinning, 1);
	__type(key, struct key_4);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} private_ranges SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16);
	__uint(pinning, 1);
	__type(key, struct key_6);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} private_ranges_v6 SEC(".maps");

	SEC("classifier")
int bpf_main(struct __sk_buff *skb)
{
	int ret;
	struct val *rec;
	struct val v = {
		.pad = 0,
		.up_bytes = 0,
		.up_pkts = 1,
		.down_bytes = 0,
		.down_pkts = 1,
	};
	void *data = (void *)(unsigned long)skb->data;
	void *data_end = (void *)(unsigned long)skb->data_end;
	struct ethhdr *eth = (struct ethhdr *)(data);


	if(skb->protocol == bpf_ntohs(ETH_P_IP)){
		struct iphdr *iph = (struct iphdr *)(eth + 1);
		__u32 src, dst;
		struct key_4 src_key, dst_key;

		if ((void *)(iph + 1) > data_end)
			return TC_ACT_OK;
		src = iph->saddr;
		dst = iph->daddr;

		dst_key.prefixlen = 32;
		dst_key.v4_addr = dst;

		src_key.prefixlen = 32;
		src_key.v4_addr = src;

		if (bpf_map_lookup_elem(&valid_v4, &dst_key) && (!bpf_map_lookup_elem(&private_ranges, &src_key))) {
			rec = bpf_map_lookup_elem(&v4_stats, &dst);
			if (!rec) {
				v.down_bytes = skb->len;
				memcpy(v.mac, eth->h_dest, ETH_ALEN);
				ret = bpf_map_update_elem(&v4_stats, &dst, &v, 0);
				if (!ret){
					return TC_ACT_OK;
				}
			} else {
				lock_xadd(&rec->down_bytes, skb->len);
				lock_xadd(&rec->down_pkts, 1);
				memcpy(rec->mac, eth->h_dest, ETH_ALEN);
			}
		}else if (bpf_map_lookup_elem(&valid_v4, &src_key) && (!bpf_map_lookup_elem(&private_ranges, &dst_key))){
			rec = bpf_map_lookup_elem(&v4_stats, &src);
			if (!rec) {
				v.up_bytes = skb->len;
				memcpy(v.mac, eth->h_source, ETH_ALEN);
				ret = bpf_map_update_elem(&v4_stats, &src, &v, 0);
				if (!ret){
					return TC_ACT_OK;
				}
			} else {
				lock_xadd(&rec->up_bytes, skb->len);
				lock_xadd(&rec->up_pkts, 1);
				memcpy(rec->mac, eth->h_source, ETH_ALEN);
			}
		}
	} else if (skb->protocol == bpf_ntohs(ETH_P_IPV6)) {
		struct key_6 dst_key, src_key;
		struct ipv6hdr *ip6hdr = (struct ipv6hdr *)(eth + 1);

		if (ip6hdr + 1 > data_end)
			return TC_ACT_OK;

		src_key.prefixlen = 128;
		dst_key.prefixlen = 128;
		memcpy(src_key.v6_addr, ip6hdr->saddr.in6_u.u6_addr32, 16);
		memcpy(dst_key.v6_addr, ip6hdr->daddr.in6_u.u6_addr32, 16);


		if (bpf_map_lookup_elem(&valid_v6, &dst_key) && (!bpf_map_lookup_elem(&private_ranges_v6, &src_key))) {
			rec = bpf_map_lookup_elem(&v6_stats, dst_key.v6_addr);
			if (!rec) {
				v.down_bytes = skb->len;
				memcpy(v.mac, eth->h_dest, ETH_ALEN);
				ret = bpf_map_update_elem(&v6_stats, dst_key.v6_addr, &v, 0);
				if (!ret){
					return TC_ACT_OK;
				}
			} else {
				lock_xadd(&rec->down_bytes, skb->len);
				lock_xadd(&rec->down_pkts, 1);
				memcpy(rec->mac, eth->h_dest, ETH_ALEN);
			}
		}else if (bpf_map_lookup_elem(&valid_v6, &src_key) && (!bpf_map_lookup_elem(&private_ranges_v6, &dst_key))) {
			rec = bpf_map_lookup_elem(&v6_stats, src_key.v6_addr);
			if (!rec) {
				v.up_bytes = skb->len;
				memcpy(v.mac, eth->h_source, ETH_ALEN);
				ret = bpf_map_update_elem(&v6_stats, src_key.v6_addr, &v, 0);
				if (!ret)
					return TC_ACT_OK;
			} else {
				lock_xadd(&rec->up_bytes, skb->len);
				lock_xadd(&rec->up_pkts, 1);
				memcpy(rec->mac, eth->h_source, ETH_ALEN);
			}
		}
	}
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
