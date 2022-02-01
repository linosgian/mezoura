#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/resource.h>
#include "mezoura.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif


static const struct {
	const char *name;
} bpf_map_info[] = {
	[BPF_MAP_V4_STATS] = { "v4_stats" },
	[BPF_MAP_V6_STATS] = { "v6_stats" },
	[BPF_MAP_VALID_V4] = { "valid_v4" },
	[BPF_MAP_VALID_V6] = { "valid_v6" },
	[BPF_MAP_PRIVATE_RANGES] = { "private_ranges" },
	[BPF_MAP_PRIVATE_RANGES_V6] = { "private_ranges_v6" },
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void mezoura_init_env(void)
{
	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	libbpf_set_print(libbpf_print_fn);

	if (setrlimit(RLIMIT_MEMLOCK, &limit)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}


static const char * bpf_map_path(enum bpf_map_id id)
{
	static char path[128];
	const char *name;

	if (id >= ARRAY_SIZE(bpf_map_info))
		return NULL;

	name = bpf_map_info[id].name;
	if (!name)
		return NULL;

	snprintf(path, sizeof(path), "%s/%s", CLS_DATA_PATH, name);

	return path;
}

static int bpf_map_get_fd(enum bpf_map_id id)
{
	const char *path = bpf_map_path(id);
	int fd;

	if (!path)
		return -1;

	fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "Failed to open map %s: %s\n", path, strerror(errno));

	return fd;
}

static int init_maps(struct config *cfg)
{
	int i;

	for (i = 0; i < __BPF_MAP_MAX; i++) {
		cfg->bpf_map_fds[i] = bpf_map_get_fd(i);
		if (cfg->bpf_map_fds[i] < 0)
			return -1;
	}

	struct bpf_lpm_trie_key *key_ipv6;
	int one = 1;

	struct subnet private_ranges[] = {
		{
			.address = "10.0.0.0",
			.mask = 8,
		},
		{
			.address = "172.16.0.0",
			.mask = 12,
		},
		{
			.address = "192.168.0.0",
			.mask = 16,
		},
	};

	if (cfg->v6_subnet.address){
		key_ipv6 = alloca(sizeof(*key_ipv6) + sizeof(__u32) * 4);
		key_ipv6->prefixlen = cfg->v6_subnet.mask;
		memcpy(key_ipv6->data, cfg->v6_subnet.address, sizeof(__u32) * 4);

		bpf_map_update_elem(cfg->bpf_map_fds[BPF_MAP_VALID_V6], key_ipv6, &one, 0);

		// Consider traffic from v6 -> v6 using non-ULA addresses as internal
		bpf_map_update_elem(cfg->bpf_map_fds[BPF_MAP_PRIVATE_RANGES_V6], key_ipv6, &one, 0);

		key_ipv6->prefixlen = 7;
		inet_pton(AF_INET6, "fc00::", key_ipv6->data);
		bpf_map_update_elem(cfg->bpf_map_fds[BPF_MAP_PRIVATE_RANGES_V6], key_ipv6, &one, 0);
	}

	for (i = 0; i < cfg->interfaces_num; i++){
		struct bpf_lpm_trie_key *key;
		key = alloca(sizeof(*key) + sizeof(__u32));

		memcpy(key->data, cfg->valid_ranges_v4[i].address, sizeof(__u32));

		key->prefixlen = cfg->valid_ranges_v4[i].mask;
		bpf_map_update_elem(cfg->bpf_map_fds[BPF_MAP_VALID_V4], key, &one, 0);
	}

	for (i = 0; i < ARRAY_SIZE(private_ranges); i++){
		struct bpf_lpm_trie_key *key;
		key = alloca(sizeof(*key) + sizeof(__u32));

		inet_pton(AF_INET, private_ranges[i].address, key->data);

		key->prefixlen = private_ranges[i].mask;
		bpf_map_update_elem(cfg->bpf_map_fds[BPF_MAP_PRIVATE_RANGES], key, &one, 0);
	}
	return 0;
}

int load_cls_and_pin_maps(struct config *cfg)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			.pin_root_path = CLS_DATA_PATH,
			);
	mezoura_init_env();
	int err;
	struct bpf_object *obj;
	struct bpf_program *bpf_prog;
	obj = bpf_object__open_file(CLS_PROG_PATH, &opts);
	err = libbpf_get_error(obj);
	if (err) {
		perror("bpf_object__open_file");
		return -1;
	}

	bpf_prog = bpf_object__find_program_by_title(obj, "classifier");
	bpf_program__set_type(bpf_prog, BPF_PROG_TYPE_SCHED_CLS);
	if (!bpf_prog) {
		fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", "classifier");
		return -1;
	}

	err = bpf_object__load(obj);
	if (err) {
		perror("bpf_object__load");
		return -1;
	}

	libbpf_set_print(NULL);
	unlink(CLS_PIN_PATH);
	err = bpf_program__pin(bpf_prog, CLS_PIN_PATH);
	if (err) {
		fprintf(stderr, "Failed to pin program to %s: %s\n",
				CLS_PIN_PATH, strerror(-err));
		return -1;
	}
	init_maps(cfg);

	bpf_object__close(obj);
	return 0;
}

