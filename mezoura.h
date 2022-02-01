#ifndef __MEZOURA_H
#define __MEZOURA_H

#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include "prometheus.h"
#include "hashmap.h"

#define CLS_PROG_PATH	"/lib/bpf/mezoura.bpf.o"
#define CLS_PIN_PATH	"/sys/fs/bpf/mezoura"
#define CLS_DATA_PATH	"/sys/fs/bpf/mezoura_data"
#define MAXINTERFACESLEN 5
#define ETH_STR_LEN 17
#define DEFAULT_PROM_PORT 9999
#define EXPORTER_INTERVAL 5

enum {
	LEASE_ATTR_IP,
	LEASE_ATTR_MAC,
	LEASE_ATTR_DUID,
	LEASE_ATTR_HOSTID,
	LEASE_ATTR_LEASETIME,
	LEASE_ATTR_NAME,
	LEASE_ATTR_MAX
};

enum bpf_map_id {
	BPF_MAP_V4_STATS,
	BPF_MAP_V6_STATS,
	BPF_MAP_VALID_V4,
	BPF_MAP_VALID_V6,
	BPF_MAP_PRIVATE_RANGES,
	BPF_MAP_PRIVATE_RANGES_V6,
	__BPF_MAP_MAX,
};

struct subnet {
	char *address;
	int mask;
};

struct host {
	char *hostname;
	char *hostname6;
};

struct prom_def {
	prom_metric *download_metric;
	prom_metric *download_pkt_metric;
	prom_metric *upload_metric;
	prom_metric *upload_pkt_metric;
};

struct config {
	char *ifnames[MAXINTERFACESLEN];
	struct hashmap_s ips;
	struct hashmap_s hosts;
	int exporter_port;
	int exporter_interval;
	int bpf_map_fds[__BPF_MAP_MAX];
	int interfaces_num;
	prom_metric_def *upload_metric;
	prom_metric_def *upload_pkt_metric;
	prom_metric_def *download_metric;
	prom_metric_def *download_pkt_metric;
	prom_metric_set metrics;
	struct subnet v6_subnet;
	struct subnet valid_ranges_v4[MAXINTERFACESLEN];
};

int load_cls_and_pin_maps(struct config *cfg);
int cmd_add_qdisc(struct config *cfg);
int parse_uci_config(struct config *cfg);
void iterate_map(struct config *cfg, int map_fd, int family, void* key);

#endif
