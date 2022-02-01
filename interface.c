#include <sys/socket.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/ether.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <uci.h>
#include <uci_blob.h>
#include "mezoura.bpf.h"
#include "mezoura.h"


const struct blobmsg_policy lease_attrs[LEASE_ATTR_MAX] = {
	[LEASE_ATTR_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_DUID] = { .name = "duid", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_HOSTID] = { .name = "hostid", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_LEASETIME] = { .name = "leasetime", .type = BLOBMSG_TYPE_STRING },
	[LEASE_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list lease_attr_list = {
	.n_params = LEASE_ATTR_MAX,
	.params = lease_attrs,
};

static int run_cmd(char *cmd, bool ignore)
{
	char *argv[] = { "sh", "-c", cmd, NULL };
	bool first = true;
	int status = -1;
	char buf[512];
	int fds[2];
	FILE *f;
	int pid;

	if (pipe(fds))
		return -1;

	pid = fork();
	if (!pid) {
		close(fds[0]);
		if (fds[1] != STDOUT_FILENO)
			dup2(fds[1], STDOUT_FILENO);
		if (fds[1] != STDERR_FILENO)
			dup2(fds[1], STDERR_FILENO);
		if (fds[1] > STDERR_FILENO)
			close(fds[1]);
		execv("/bin/sh", argv);
		exit(1);
	}

	if (pid < 0)
		return -1;

	close(fds[1]);
	f = fdopen(fds[0], "r");
	if (!f) {
		close(fds[0]);
		goto out;
	}

	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (!strlen(buf))
			break;
		if (ignore)
			continue;
		if (first) {
			fprintf(stderr, "Command: %s\n", cmd);
			first = false;
		}
		fprintf(stderr, "%s%s", buf, strchr(buf, '\n') ? "" : "\n");
	}

	fclose(f);

out:
	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			break;

	return status;
}

int cmd_add_qdisc(struct config *cfg) {
	char buf[256];

	for (int i = 0; i < cfg->interfaces_num; i++){
		snprintf(buf, sizeof(buf), "tc qdisc add dev %s clsact", cfg->ifnames[i]);
		run_cmd(buf, false);
		snprintf(buf, sizeof(buf), "tc filter del dev %s ingress", cfg->ifnames[i]);
		run_cmd(buf, false);
		snprintf(buf, sizeof(buf), "tc filter del dev %s egress", cfg->ifnames[i]);
		run_cmd(buf, false);
		snprintf(buf, sizeof(buf), "tc filter add dev %s ingress bpf object-pinned %s", cfg->ifnames[i], CLS_PIN_PATH);
		run_cmd(buf, false);
		snprintf(buf, sizeof(buf), "tc filter add dev %s egress bpf object-pinned %s", cfg->ifnames[i], CLS_PIN_PATH);
		run_cmd(buf, false);
	}
	return 0;
}

static struct blob_buf b;

/*
 * Parse all `host` entries in the `dhcp` uci config
 * to map MAC addresses -> hostnames
 */
int parse_uci_config(struct config *cfg)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *dhcp = NULL;
	struct uci_element *e;

	int err = uci_load(uci, "dhcp", &dhcp);
	if (err)
		return -1;

	uci_foreach_element(&dhcp->sections, e) {
		char *mac = NULL, *hostname = NULL;
		struct host *h = malloc(sizeof(struct host));
		struct uci_section *s = uci_to_section(e);
		if (!strcmp(s->type, "host")){
			blob_buf_init(&b, 0);
			uci_to_blob(&b, s, &lease_attr_list);
			struct blob_attr *tb[LEASE_ATTR_MAX], *c;

			blobmsg_parse(lease_attrs, LEASE_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));
			if ((c = tb[LEASE_ATTR_MAC])){
				mac = strdup(blobmsg_get_string(c));
				if (!mac)
					return -1;
			}
			if ((c = tb[LEASE_ATTR_NAME])) {
				hostname = strdup(blobmsg_get_string(c));
				if (!hostname)
					return -1;
			}
			h->hostname = hostname;

			char *buf = malloc(256);
			snprintf(buf, 256, "%s%s", h->hostname, "-v6");
			h->hostname6 = buf;
			if (hashmap_put(&cfg->hosts, mac, strlen(mac), h) != 0) {
				fprintf(stderr,
						"ERR: failed to put host in hashmap: \n");
				return -1;
			}
		}
	}
	return 0;
}

void iterate_map(struct config *cfg, int map_fd, int family, void* key)
{
	int addrlen = family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
	int err;
	struct val v;
	void *keyp = key, *prev_keyp = NULL;
	while (true) {
		err = bpf_map_get_next_key(map_fd, prev_keyp, keyp);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if ((bpf_map_lookup_elem(map_fd, keyp, &v)) != 0) {
			fprintf(stderr,
					"ERR: bpf_map_lookup_elem failed key:\n");
			goto next;
		}

		struct prom_def *d;
		char *ip = malloc(addrlen);
		if (inet_ntop(family, key, ip, addrlen) == NULL){
			goto next;
		}
		d = (struct prom_def *)hashmap_get(&cfg->ips, ip, strlen(ip));
		if (!d) {
			d = malloc(sizeof(struct prom_def));
			prom_label l_ip = {
				.key = "ip",
				.value = ip
			};

			struct ether_addr mc;
			memcpy(mc.ether_addr_octet, v.mac, ETH_ALEN);
			char *mac = malloc(ETH_STR_LEN);

			if (!ether_ntoa_r(&mc, mac)){
				free(ip);
				free(mac);
				goto next;
			}

			struct host *h = (struct host *)hashmap_get(&cfg->hosts, mac, strlen(mac));
			if (!h) {
				fprintf(stderr, "No mac found for ip: %s\n", ip);
				free(ip);
				free(mac);
				goto next;
			}
			prom_label l_mac = {"mac", mac};

			prom_label l_hostname;
			if (family == AF_INET6){
				l_hostname.key = "hostname";
				l_hostname.value = h->hostname6;
			}else{
				l_hostname.key = "hostname";
				l_hostname.value = h->hostname;
			}

			d->download_metric = prom_get(&cfg->metrics, cfg->download_metric, 3,
					l_mac, l_hostname, l_ip);
			d->download_pkt_metric = prom_get(&cfg->metrics, cfg->download_pkt_metric, 3,
					l_mac, l_hostname, l_ip);

			d->upload_metric = prom_get(&cfg->metrics, cfg->upload_metric, 3,
					l_mac, l_hostname, l_ip);
			d->upload_pkt_metric = prom_get(&cfg->metrics, cfg->upload_pkt_metric, 3,
					l_mac, l_hostname, l_ip);
			if (hashmap_put(&cfg->ips, ip, strlen(ip), d) != 0) {
				fprintf(stderr,
						"ERR: failed to put IP in hashmap: %s\n", ip);
				free(ip);
				goto next;
			}
		}else{
			free(ip);
		}

		d->upload_metric->value = v.up_bytes;
		d->upload_pkt_metric->value = v.up_pkts;
		d->download_metric->value = v.down_bytes;
		d->download_pkt_metric->value = v.down_pkts;
next:
		prev_keyp = keyp;
	}
}
