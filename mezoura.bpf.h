struct key_4 {
	__u32 prefixlen;
	__u32 v4_addr;
}; 

struct key_6 {
	__u32 prefixlen;
	__u32 v6_addr[4];
};

struct val {
	__u8 mac[ETH_ALEN];
	__u16 pad;
	__u64 down_bytes;
	__u64 up_bytes;
	__u64 down_pkts;
	__u64 up_pkts;
};
