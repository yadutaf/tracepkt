# Tracepkt

Trace a ping packet on the L2 layer, as it crosses Linux network interfaces and namespaces. Supports IPv4 and IPv6.

```console
> modprobe ip_tables ip6_tables
> sudo python tracepkt.py 172.17.0.2
    NETWORK NS        INTERFACE    TYPE ADDRESSES                          IPTABLES
[           0]                  request 172.17.0.1 -> 172.17.0.2               nat.OUTPUT      :ACCEPT
[           0]                  request 172.17.0.1 -> 172.17.0.2            filter.OUTPUT      :ACCEPT
[  4026531992]          docker0 request 172.17.0.1 -> 172.17.0.2               nat.POSTROUTING :ACCEPT
[  4026531992]          docker0 request 172.17.0.1 -> 172.17.0.2          
[  4026531992]      veth61528aa request 172.17.0.1 -> 172.17.0.2          
[  4026533448]             eth0 request 172.17.0.1 -> 172.17.0.2          
[  4026533448]             eth0   reply 172.17.0.2 -> 172.17.0.1          
[  4026531992]      veth61528aa   reply 172.17.0.2 -> 172.17.0.1          
[  4026531992]          docker0   reply 172.17.0.2 -> 172.17.0.1          
[  4026531992]          docker0   reply 172.17.0.2 -> 172.17.0.1            filter.INPUT       :ACCEPT
```

The first 2 packets going from the current network namespace to a Docker container and going back, crossing a veth pair and a bridge.

## Features

* Record crossed Linux network interfaces
* Record crossed Linux network namespaces
* Record crossed iptables chains

**Note**: The iptables tracing support is ***experimental***. Tracing which specific
rule matches within a chain is not supported. This would require to hook into
``trace_packet`` netfilter function which is unfortunatly ``static`` and
therefore private.

## The full story

This project started as an illustration for a blog post on perf and eBPF https://blog.yadutaf.fr/2017/07/28/tracing-a-packet-journey-using-linux-tracepoints-perf-ebpf/.

## Usage

To use this project, you need a working / recent BCC install on your system. Read more about BCC on their Github repository: https://github.com/iovisor/bcc.

Additionally, you'll need a recent kernel (presumably >= 4.7) and full root privilege.

## License

MIT
