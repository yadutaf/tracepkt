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
    u64 proto;    // familiy (IPv4 or IPv6)
    u64 icmptype;
    u64 icmpid;   // In practice, this is the PID of the ping process (see "ident" field in https://github.com/iputils/iputils/blob/master/ping_common.c)
    u64 icmpseq;  // Sequence number
    u64 saddr[2]; // Source address. IPv4: store in saddr[0]
    u64 daddr[2]; // Dest   address. IPv4: store in daddr[0]
};
BPF_PERF_OUTPUT(route_evt);

int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *first, struct net_device *dev, struct netdev_queue *txq, int *ret)
{
    // Cast types. Intermediate cast not needed, kept for readability
    struct sock *sk = first->sk;
    struct inet_sock *inet = inet_sk(sk);

    // Built event for userland
    struct route_evt_t evt = {};

    // Pre-Compute header addresses
    char* ip_header_address   = first->head + first->network_header;
    char* icmp_header_address = first->head + first->transport_header;

    // Abstract IPv4 / IPv6
    u8 proto_icmp;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;

    // Filter IP packets
    u8 protocol;
    u16 family = sk->sk_family;
    evt.proto = sk->sk_family;
    if (family == AF_INET) {
        struct iphdr* iphdr = (struct iphdr*)ip_header_address;

        // Load protocol and address
        protocol     = iphdr->protocol;
        evt.saddr[0] = iphdr->saddr;
        evt.daddr[0] = iphdr->daddr;

        // Load constants
        proto_icmp = IPPROTO_ICMP;
        proto_icmp_echo_request = ICMP_ECHO;
        proto_icmp_echo_reply   = ICMP_ECHOREPLY;
    } else if (family == AF_INET6) {
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)ip_header_address;

        // Load protocol and address
        protocol = ipv6hdr->nexthdr;
        bpf_probe_read(evt.saddr, sizeof(ipv6hdr->saddr), (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(evt.daddr, sizeof(ipv6hdr->daddr), (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));

        // Load constants
        proto_icmp = IPPROTO_ICMPV6;
        proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
        proto_icmp_echo_reply   = ICMPV6_ECHO_REPLY;
    } else {
        return 0;
    }

    // Filter ICMP packets
    if (protocol != proto_icmp) {
        return 0;
    }

    // Filter ICMP echo request and echo reply
    struct icmphdr* icmphdr = (struct icmphdr*)icmp_header_address;
    if (icmphdr->type != proto_icmp_echo_request && icmphdr->type != proto_icmp_echo_reply) {
        return 0;
    }

    // Get ICMP info
    evt.icmptype = icmphdr->type;
    evt.icmpid   = icmphdr->un.echo.id;
    evt.icmpseq  = icmphdr->un.echo.sequence;

    // Fix endian
    evt.icmpid  = be16_to_cpu(evt.icmpid);
    evt.icmpseq = be16_to_cpu(evt.icmpseq);

    // Get netns id
#ifdef CONFIG_NET_NS
    evt.netns = sk->sk_net.net->ns.inum;
#else
    evt.netns = 0;
#endif

    // Get interface name
    bpf_probe_read(&evt.ifname, IFNAMSIZ, dev->name);

    // Send event to userland
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
};

'''

IFNAMSIZ = 16 # uapi/linux/if.h

class RouteEvt(ct.Structure):
    _fields_ = [
        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("proto",    ct.c_ulonglong),
        ("icmptype", ct.c_ulonglong),
        ("icmpid",   ct.c_ulonglong),
        ("icmpseq",  ct.c_ulonglong),
        ("saddr",    ct.c_ulonglong * 2),
        ("daddr",    ct.c_ulonglong * 2),
    ]

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(RouteEvt)).contents

    # Decode address
    if event.proto == AF_INET:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    elif event.proto == AF_INET6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)
    else:
        return

    # Decode direction
    direction = "request" if event.icmptype in [8, 128] else "reply"

    # Print event
    print "[%12s] %16s %7s #%05u.%03u %s -> %s" % (event.netns, event.ifname, direction, event.icmpid, event.icmpseq, saddr, daddr)

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_evt"].open_perf_buffer(event_printer)

    while True:
        b.kprobe_poll()
