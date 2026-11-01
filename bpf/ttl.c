// SPDX-License-Identifier: GPL-2.0-or-later
//
// In-kernel TTL / hop-limit rewriting for GKI Tether Shield.
//
// Attached as a tc (clsact) egress classifier on every upstream interface,
// it sets the IPv4 TTL (fixing the header checksum) and the IPv6 hop limit of
// each outgoing packet to the target value, so tethered traffic looks like
// the phone's own. It never drops or redirects: every path returns
// TC_ACT_UNSPEC so the packet continues to any other filters on the hook
// (Android's netd and clatd attach their own).
//
// l3_off is the offset of the IP header from skb->data: 0 on raw-IP links
// (cellular rmnet / ccmni, CLAT v4-*), ETH_HLEN on Ethernet. The loader sets
// it per program instance. The version nibble is checked against
// skb->protocol, so a wrong offset leaves packets untouched.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define IPV4_TTL_OFF   8
#define IPV4_CSUM_OFF  10
#define IPV6_HLIM_OFF  7

enum counter {
	CNT_IPV4_SEEN,
	CNT_IPV6_SEEN,
	CNT_IPV4_REWRITTEN,
	CNT_IPV6_REWRITTEN,
	CNT_MAX,
};

// Target TTL / hop limit, set by the daemon; changes apply live.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} target_ttl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

volatile const __u32 l3_off = 0;

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);

	if (v)
		*v += 1;
}

static __always_inline __u8 target(void)
{
	__u32 key = 0;
	__u32 *v = bpf_map_lookup_elem(&target_ttl, &key);

	return v && *v >= 1 && *v <= 255 ? (__u8)*v : 0;
}

static __always_inline int fix_ipv4(struct __sk_buff *skb, __u8 want)
{
	__u8 ver;
	__u16 old_word, new_word;

	if (bpf_skb_load_bytes(skb, l3_off, &ver, 1) || (ver >> 4) != 4)
		return TC_ACT_UNSPEC;
	count(CNT_IPV4_SEEN);
	// TTL shares a 16-bit checksum word with the protocol byte.
	if (bpf_skb_load_bytes(skb, l3_off + IPV4_TTL_OFF, &old_word, 2))
		return TC_ACT_UNSPEC;
	if (((__u8 *)&old_word)[0] == want)
		return TC_ACT_UNSPEC;
	new_word = old_word;
	((__u8 *)&new_word)[0] = want;
	if (bpf_l3_csum_replace(skb, l3_off + IPV4_CSUM_OFF, old_word, new_word, 2))
		return TC_ACT_UNSPEC;
	if (bpf_skb_store_bytes(skb, l3_off + IPV4_TTL_OFF, &new_word, 1, 0))
		return TC_ACT_UNSPEC;
	count(CNT_IPV4_REWRITTEN);
	return TC_ACT_UNSPEC;
}

static __always_inline int fix_ipv6(struct __sk_buff *skb, __u8 want)
{
	__u8 ver, hlim;

	if (bpf_skb_load_bytes(skb, l3_off, &ver, 1) || (ver >> 4) != 6)
		return TC_ACT_UNSPEC;
	count(CNT_IPV6_SEEN);
	if (bpf_skb_load_bytes(skb, l3_off + IPV6_HLIM_OFF, &hlim, 1) || hlim == want)
		return TC_ACT_UNSPEC;
	if (bpf_skb_store_bytes(skb, l3_off + IPV6_HLIM_OFF, &want, 1, 0))
		return TC_ACT_UNSPEC;
	count(CNT_IPV6_REWRITTEN);
	return TC_ACT_UNSPEC;
}

SEC("tc")
int fix_ttl(struct __sk_buff *skb)
{
	__u8 want = target();

	if (!want)
		return TC_ACT_UNSPEC;
	if (skb->protocol == bpf_htons(ETH_P_IP))
		return fix_ipv4(skb, want);
	if (skb->protocol == bpf_htons(ETH_P_IPV6))
		return fix_ipv6(skb, want);
	return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
