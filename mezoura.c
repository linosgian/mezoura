#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <libubox/ulog.h>
#include "mezoura.h"

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options]\n"
			"Options:\n"
			"	-l <file>	Load defaults from <file>\n"
			"	-e			Enable embedded Prometheus exporter\n"
			"	-p			Prometheus exporter port\n"
			"	-t			Prometheus exporter main loop interval\n"
			"	-4			v4 subnet to track stats for along with their interfaces, e.g. 192.168.1.0/24/eth0 (required)\n"
			"	-6			the public v6 subnet that is delegated from the ISP, e.g. 2001:db8:ca2:2::1/64\n"
			"\n", progname);

	return -1;
}

int main(int argc, char **argv)
{
	int ch, i;

	ulog_open(ULOG_SYSLOG, LOG_DAEMON, "mezoura");
	bool exporter = false;
	struct config cfg = {
		.exporter_port = DEFAULT_PROM_PORT,
		.exporter_interval = EXPORTER_INTERVAL,
		.interfaces_num = 0,
	};

	while ((ch = getopt(argc, argv, "6:4:p:t:e")) != -1) {
		switch (ch) {
			case '6':
				char *prefix = strtok(optarg, "/");
				prefix = strtok(NULL, "/");

				if (!prefix){
					fprintf(stderr, "Provide a valid v6 subnet mask\n");
					return usage(argv[0]);
				}
				cfg.v6_subnet.address = malloc(sizeof(__u32) * 4);
				if (!inet_pton(AF_INET6, optarg, cfg.v6_subnet.address)){
					fprintf(stderr, "Invalid v6 address: %s\n", optarg);
					return usage(argv[0]);
				}
				i = atoi(prefix);
				if (!i){
					fprintf(stderr, "Invalid v6 address prefix: %s\n", prefix);
					return usage(argv[0]);
				}
				cfg.v6_subnet.mask = i;
				break;
			case '4':
				char *mask = strtok(optarg, "/");
				mask = strtok(NULL, "/");
				char *iface = strtok(NULL, "/");

				if (!mask){
					fprintf(stderr, "Provide a valid v4 subnet mask\n");
					return usage(argv[0]);
				}

				cfg.valid_ranges_v4[cfg.interfaces_num].address = malloc(sizeof(__u32));
				if (!inet_pton(AF_INET, optarg, cfg.valid_ranges_v4[cfg.interfaces_num].address)){
					fprintf(stderr, "Invalid v4 address: %s\n", optarg);
					return usage(argv[0]);
				}

				i = atoi(mask);
				if (!i){
					fprintf(stderr, "Invalid v4 address mask: %s\n", mask);
					return usage(argv[0]);
				}
				cfg.valid_ranges_v4[cfg.interfaces_num].mask = i;

				if (!iface){
					fprintf(stderr, "Provide a valid interface name\n");
					return usage(argv[0]);
				}
				cfg.ifnames[cfg.interfaces_num] = iface;
				cfg.interfaces_num++;
				break;
			case 'p':
				int port = atoi(optarg);
				if (!port){
					fprintf(stderr, "Invalid prometheus exporter port: %s\n", optarg);
					return usage(argv[0]);
				}
				cfg.exporter_port = port;
				break;
			case 't':
				int interval = atoi(optarg);
				if (!interval){
					fprintf(stderr, "Invalid prometheus exporter timeout: %s\n", optarg);
					return usage(argv[0]);
				}
				cfg.exporter_interval = interval;
				break;
			case 'e':
				exporter = true;
				break;
			default:
				return usage(argv[0]);
		}
	}
	if (cfg.interfaces_num == 0){
		fprintf(stderr, "Missing required arguments\n");
		return usage(argv[0]);
	}

	if (load_cls_and_pin_maps(&cfg))
		return -1;
	cmd_add_qdisc(&cfg);

	prom_init(&cfg.metrics);
	prom_metric_def download = {"node_nat_traffic_download",
		"Total ingress bandwidth per-host", PROM_METRIC_TYPE_GAUGE};
	prom_metric_def download_pkt = {"node_nat_traffic_download_pkts",
		"Total ingress packets per-host", PROM_METRIC_TYPE_GAUGE};
	prom_metric_def upload = {"node_nat_traffic_upload",
		"Total egress bandwidth per-host", PROM_METRIC_TYPE_GAUGE};
	prom_metric_def upload_pkt = {"node_nat_traffic_upload_pkts",
		"Total egress packets per-host", PROM_METRIC_TYPE_GAUGE};

	prom_register(&cfg.metrics, &download);
	prom_register(&cfg.metrics, &download_pkt);
	prom_register(&cfg.metrics, &upload);
	prom_register(&cfg.metrics, &upload_pkt);
	cfg.upload_metric = &upload;
	cfg.upload_pkt_metric = &upload_pkt;
	cfg.download_metric = &download;
	cfg.download_pkt_metric = &download_pkt;

	if (hashmap_create(256, &cfg.ips) != 0){
		fprintf(stderr,
				"ERR: failed to initialize IP hashmap\n");
		return -1;
	}

	if (hashmap_create(256, &cfg.hosts) != 0){
		fprintf(stderr,
				"ERR: failed to initialize hosts hashmap\n");
		return -1;
	}

	if (parse_uci_config(&cfg)){
		fprintf(stderr,
				"ERR: failed to parse uci dhcp hosts config\n");
		return -1;
	}
	int pid = fork();
	if (pid != 0) {
		while (1) {
			__u32 key;
			iterate_map(&cfg, cfg.bpf_map_fds[BPF_MAP_V4_STATS], AF_INET, &key);

			__u32 key6[4];
			iterate_map(&cfg, cfg.bpf_map_fds[BPF_MAP_V6_STATS], AF_INET6, key6);

			prom_flush(&cfg.metrics);
			sleep(cfg.exporter_interval);
		}
	} else {
		if (exporter)
			prom_start_server(&cfg.metrics, cfg.exporter_port);
	}
	return 0;
}
