# Tracepkt

Trace a ping packet journey across network interfaces and namespace on recent Linux. Supports IPv4 and IPv6.

```
> ping 172.17.0.2 &
> sudo python tracepkt.py
[  4026531957]          docker0 request #13796.001 172.17.0.1 -> 172.17.0.2
[  4026531957]      veth0e65931 request #13796.001 172.17.0.1 -> 172.17.0.2
[  4026532395]             eth0   reply #13796.001 172.17.0.2 -> 172.17.0.1
[  4026531957]          docker0 request #13796.002 172.17.0.1 -> 172.17.0.2
[  4026531957]      veth0e65931 request #13796.002 172.17.0.1 -> 172.17.0.2
[  4026532395]             eth0   reply #13796.002 172.17.0.2 -> 172.17.0.1
...
```

The first 2 packets going from the current network namespace to a Docker container and going back, crossing a veth pair and a bridge.

## The full story

This repository started as an illustration for https://blog.yadutaf.fr/2017/07/11/tracing-a-packet-journey-thanks-to-ebpf/

## Usage

To use this project, you need a working / recent BCC install on your system. Read more about BCC on their Github repository: https://github.com/iovisor/bcc.

Additionally, you'll need a recent kernel (presumably >= 4.4) and full root privilege.

## License

MIT

