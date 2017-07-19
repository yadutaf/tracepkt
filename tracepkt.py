#!/usr/bin/env python
# coding: utf-8

from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
from struct import pack

bpf_text = '''
#include <net/inet_sock.h>
#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>

// Event structure
struct route_evt_t {
    /* Routing information */
    char ifname[IFNAMSIZ];
    u64 netns;

    /* Packet type (IPv4 or IPv6) and address */
    u64 ip_version; // familiy (IPv4 or IPv6)
    u64 icmptype;
    u64 icmpid;     // In practice, this is the PID of the ping process (see "ident" field in https://github.com/iputils/iputils/blob/master/ping_common.c)
    u64 icmpseq;    // Sequence number
    u64 saddr[2];   // Source address. IPv4: store in saddr[0]
    u64 daddr[2];   // Dest   address. IPv4: store in daddr[0]
};
BPF_PERF_OUTPUT(route_evt);

/**
  * Common tracepoint handler. Detect IPv4/IPv6 ICMP echo request and replies and
  * emit event with address, interface and namespace.
  */
static inline int do_trace(void* ctx, struct sk_buff* skb)
{
    // Get socket pointer
    struct sock *sk;
    bpf_probe_read(&sk, sizeof(skb->sk), ((char*)skb) + offsetof(typeof(*skb), sk));

    // Get device pointer, we'll need it to get the name and network namespace
    struct net_device *dev;
    bpf_probe_read(&dev, sizeof(skb->dev), ((char*)skb) + offsetof(typeof(*skb), dev));

    // Prepare event
    struct route_evt_t evt = {};

    // Compute MAC header address
    char* head;
    u16 mac_header;

    bpf_probe_read(&head,        sizeof(skb->head),       ((char*)skb) + offsetof(typeof(*skb), head));
    bpf_probe_read(&mac_header,  sizeof(skb->mac_header), ((char*)skb) + offsetof(typeof(*skb), mac_header));

    // Compute IP Header address
    char* ip_header_address = head + mac_header + 14; // FIXME: hard-coded constant

    // Abstract IPv4 / IPv6
    u8 proto_icmp;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    u8 icmp_offset_from_ip_header;
    u8 l4proto;

    // Load IP protocol version
    bpf_probe_read(&evt.ip_version, sizeof(u8), ip_header_address);
    evt.ip_version = evt.ip_version >> 4 & 0xf;

    // Filter IP packets
    if (evt.ip_version == 4) {
        // Load IP Header
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);

        // Load protocol and address
        icmp_offset_from_ip_header = iphdr.ihl * 4;
        l4proto      = iphdr.protocol;
        evt.saddr[0] = iphdr.saddr;
        evt.daddr[0] = iphdr.daddr;

        // Load constants
        proto_icmp = IPPROTO_ICMP;
        proto_icmp_echo_request = ICMP_ECHO;
        proto_icmp_echo_reply   = ICMP_ECHOREPLY;
    } else if (evt.ip_version == 6) {
        // Assume no option header --> fixed size header
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)ip_header_address;
        icmp_offset_from_ip_header = sizeof(*ipv6hdr);

        // Load protocol and address
        bpf_probe_read(&l4proto,  sizeof(ipv6hdr->nexthdr), (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(evt.saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(evt.daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));

        // Load constants
        proto_icmp = IPPROTO_ICMPV6;
        proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
        proto_icmp_echo_reply   = ICMPV6_ECHO_REPLY;
    } else {
        return 0;
    }

    // Filter ICMP packets
    if (l4proto != proto_icmp) {
        return 0;
    }

    // Compute ICMP header address and load ICMP header
    char* icmp_header_address = ip_header_address + icmp_offset_from_ip_header;
    struct icmphdr icmphdr;
    bpf_probe_read(&icmphdr, sizeof(icmphdr), icmp_header_address);

    // Filter ICMP echo request and echo reply
    if (icmphdr.type != proto_icmp_echo_request && icmphdr.type != proto_icmp_echo_reply) {
        return 0;
    }

    // Get ICMP info
    evt.icmptype = icmphdr.type;
    evt.icmpid   = icmphdr.un.echo.id;
    evt.icmpseq  = icmphdr.un.echo.sequence;

    // Fix endian
    evt.icmpid  = be16_to_cpu(evt.icmpid);
    evt.icmpseq = be16_to_cpu(evt.icmpseq);

    // Get netns id. The code below is equivalent to: evt.netns = dev->nd_net.net->ns.inum
#ifdef CONFIG_NET_NS
    // Load net address
    struct net* net;
    possible_net_t  *skc_net = &dev->nd_net;
    bpf_probe_read(&net, sizeof(net), ((char*)skc_net) + offsetof(typeof(*skc_net), net));

    // Load ns address
    struct ns_common* ns = (struct ns_common*)(((char*)net) + offsetof(typeof(*net), ns));

    // Load inum
    bpf_probe_read(&evt.netns, sizeof(ns->inum), ((char*)ns) + offsetof(typeof(*ns), inum));
#endif

    // Load interface name
    bpf_probe_read(&evt.ifname, IFNAMSIZ, dev->name);

    // Send event
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

/**
  * Attach to Kernel Tracepoints
  */

TRACEPOINT_PROBE(net, netif_rx) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, net_dev_queue) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, napi_gro_receive_entry) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, netif_receive_skb_entry) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}

'''

IFNAMSIZ = 16 # uapi/linux/if.h

class TestEvt(ct.Structure):
    _fields_ = [
        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("icmptype",    ct.c_ulonglong),
        ("icmpid",      ct.c_ulonglong),
        ("icmpseq",     ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),
    ]

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(TestEvt)).contents

    # Decode address
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    elif event.ip_version == 6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)
    else:
        return

    # Decode direction
    if event.icmptype in [8, 128]:
        direction = "request"
    elif event.icmptype in [0, 129]:
        direction = "reply"
    else:
        return

    # Print event
    print "[%12s] %16s %7s #%05u.%03u %s -> %s" % (event.netns, event.ifname, direction, event.icmpid, event.icmpseq, saddr, daddr)

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_evt"].open_perf_buffer(event_printer)

    while True:
        b.kprobe_poll()

