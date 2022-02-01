#ifndef __PROMETHEUS_H
#define __PROMETHEUS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

static const char PROM_METRIC_TYPE_COUNTER[]   = "counter";
static const char PROM_METRIC_TYPE_GAUGE[]     = "gauge";
static const char PROM_METRIC_TYPE_HISTOGRAM[] = "histogram";
static const char PROM_METRIC_TYPE_SUMMARY[]   = "summary";

#ifndef PROM_MAX_LABELS
#define PROM_MAX_LABELS 50
#endif

#ifndef PROM_MAX_METRICS
#define PROM_MAX_METRICS 256
#endif

#ifndef PROM_BUF_SIZE
#define PROM_BUF_SIZE 1024
#endif

#define PROM_CONN_BACKLOG 100

// Generic definition for a metric including name, help and type
typedef struct prom_metric_def {
	char *name;
	char *help;
	const char *type;
} prom_metric_def;

// Key-value pair representing a label name with an assigned value
typedef struct prom_label {
	char *key;
	char *value;
} prom_label;

// Represents an instance of a metric with a given value and set of labels
typedef struct prom_metric {
	int num_labels;
	struct prom_label labels[PROM_MAX_LABELS];
	unsigned long long int value;
} prom_metric;

// A container for metrics that share a common definition
typedef struct prom_metric_def_set {
	prom_metric_def *def;
	int n_metrics;
	prom_metric *metrics[PROM_MAX_METRICS];
} prom_metric_def_set;

// Container for a set of references to prom_metrics
typedef struct prom_metric_set {
	char *fname;
	int n_defs;
	prom_metric_def_set *defs[PROM_MAX_METRICS];
} prom_metric_set;

void prom_init(prom_metric_set *s);

void prom_register(prom_metric_set *s, prom_metric_def *d);

// Initializes a prom_metric with a zero value and empty label set
void prom_metric_init(prom_metric *m);

// Sets a label key and value on the given metric value
void prom_metric_set_label(prom_metric *m, char *key, char *value);

prom_metric *prom_get(prom_metric_set *s, prom_metric_def *d, int n, ...);

void _prom_escape(char *buf, char *str);

// Prints the metric value to the given IO
void prom_metric_write(prom_metric_def_set *s, int f);

// Writes metrics out to the temp file
int prom_flush(prom_metric_set *s);

int prom_cleanup(prom_metric_set *s);

void prom_http_write_header(int sock);

int prom_start_server(prom_metric_set *s, int port);

#endif // PROMETHEUS_H
