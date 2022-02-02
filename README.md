# Mezoura - TC eBPF classifier based traffic accounting

### About

Mezoura utilizes TC's direct-action eBPF hook to add a "classifier" (also known as "filter").
TC or traffic control is a Linux subsystem that's used to manipulate network
traffic. It has many use cases such as Quality of Service (impose delays or
bandwidth limits for flows, simulate packet drops and so on).
For more info in regards to TC and the eBPF hooks it contains, refer to [this](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)

TC filters are attached to "qdiscs" (or Queuing Discipline) in order to classify
traffic based on the "classes" that we have attached to the qdisc at hand.

Mezoura uses this eBPF hook, to monitor traffic coming in and going out of an
interface. It can be attached to any interface but will only look for traffic
from/to the internet (in other words, to/from non-private IPs). It works for
both IPv4 and v6.

Each packet that passes through ingress/egress will be parsed by Mezoura, and
from that the following values will be updated:

1. MAC Address
2. Download bytes/packets
3. Upload bytes/packets

NOTE: The eBPF program has access to the whole packet, therefore, more
information can be extracted. I've kept is simple, since this will run for every
packet passing through.

Then, a userspace daemon will read these stats from the eBPF maps (one for v4
and one for v6) and pass them to the embedded Prometheus exporter.

The stats will be written to `/tmp/prom_c` and also exposed through the embedded
exporter on port 9999 (by default). One can opt out of the HTTP service for
the prometheus exporter, and consume the file mentioned above directly (with
[prometheus-node-exporter-lua-textfile](https://openwrt.org/packages/pkgdata/prometheus-node-exporter-lua-textfile)).

Mezoura utilizes OpenWRT `uci` (libuci) facility to read all `host` entries from the
`dhcp` section. These can be found under `/etc/config/dhcp`. For instance,

```
#~ cat /etc/config/dhcp
config host
	option name 'foo'
	option dns '1'
	option ip '192.168.1.2'
	option mac 'XX:XX:XX:XX:XX:XX'
```

For each entry found in the eBPF maps, the MAC -> hostname resolution is looked
up using the information mentioned above. If the MAC is not known, the entry is skipped.

### Usage
Note that there is an init script and default config for Mezoura, included
[here](https://github.com/openwrt/packages/pull/17771)

<dl>
<dt>-e</dt>
<dd>Enable embedded Prometheus exporter.</dd>

<dt>-p port_number</dt>
<dd>The port number for the Prometheus exporter.</dd>

<dt>-4 address/mask/interface</dt>
<dd>v4 subnet to track stats for along with their interfaces, e.g. 192.168.1.0/24/eth0 (required).</dd>

<dt>-6 address/mask</dt>
<dd>the public v6 subnet that is delegated from the ISP, e.g. 2001:db8:ca2:2::1/64.</dd>

<dt>-t sec</dt>
<dd>Prometheus exporter main loop interval.</dd>

</dl>


### Examples

```
mezoura -e -4 192.168.2.1/24/br-lan -4 192.168.2.3/24/br-foo -6 2001:db8:ca2:2::1/64 -t 10
```

This will monitor traffic for `br-lan` and `br-foo` (these are Linux interfaces,
not OpenWRT logical interfaces - e.g. `lan`), and the `/64` v6 subnet that's
delegated from the ISP. Lastly, a 10 second interval is provided to the
Prometheus exporter (how often stats will be pulled from the eBPF maps).

```
mezoura -4 192.168.2.1/24/br-lan
```

This is the bare minimum setup, where a single bridge interface is monitored,
without v6, and without the embedded Prometheus exporter.

The output looks like this:

```
# TYPE node_nat_traffic_download gauge
# HELP node_nat_traffic_download Total ingress bandwidth per-host
node_nat_traffic_download{mac="XX:XX:XX:XX:XX:XX",hostname="koko",ip="192.168.3.200"} 297794
node_nat_traffic_download{mac="XX:XX:XX:XX:XX:XX",hostname="koko-v6",ip="2a02::"} 1205089727
# TYPE node_nat_traffic_download_pkts gauge
# HELP node_nat_traffic_download_pkts Total ingress packets per-host
node_nat_traffic_download_pkts{mac="XX:XX:XX:XX:XX:XX",hostname="koko",ip="192.168.3.200"} 3006
node_nat_traffic_download_pkts{mac="XX:XX:XX:XX:XX:XX",hostname="koko-v6",ip="2a02::"} 30000
# TYPE node_nat_traffic_upload gauge
# HELP node_nat_traffic_upload Total egress bandwidth per-host
node_nat_traffic_upload{mac="XX:XX:XX:XX:XX:XX",hostname="koko",ip="192.168.3.200"} 257410
node_nat_traffic_upload{mac="XX:XX:XX:XX:XX:XX",hostname="koko-v6",ip="2a02::"} 1205089
# TYPE node_nat_traffic_upload_pkts gauge
# HELP node_nat_traffic_upload_pkts Total egress packets per-host
node_nat_traffic_upload_pkts{mac="XX:XX:XX:XX:XX:XX",hostname="koko",ip="192.168.3.200"} 3005
node_nat_traffic_upload_pkts{mac="XX:XX:XX:XX:XX:XX",hostname="koko-v6",ip="2a02::"} 50000
```
