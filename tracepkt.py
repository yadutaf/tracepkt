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
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u64 netns;

    /* Packet type (IPv4 or IPv6) and address */
    u64 proto;    // familiy << 16
    u64 l4proto;
    u64 icmptype;
    u64 icmpid;   // In practice, this is the PID of the ping process (see "ident" field in https://github.com/iputils/iputils/blob/master/ping_common.c)
    u64 icmpseq;  // Sequence number
    u64 saddr[2]; // Source address. IPv4: store in saddr[0]
    u64 daddr[2]; // Dest   address. IPv4: store in daddr[0]
};
BPF_PERF_OUTPUT(route_evt);

#define member_size(type, member) sizeof(((type *)0)->member)

int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *first, struct net_device *dev, struct netdev_queue *txq, int *ret)
{

    // Cast types. Intermediate cast not needed, kept for readability
    struct sock *sk = first->sk;
    struct inet_sock *inet = inet_sk(sk);

    // Built event for userland
    struct route_evt_t evt = {};
    bpf_get_current_comm(evt.comm, TASK_COMM_LEN);

    // Filter IP packets
    u16 family = sk->__sk_common.skc_family;
    u16 iphdroffset = first->network_header;
    u16 icmphdroffset = first->transport_header;
    evt.proto = family << 16;
    u8 proto_icmp;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    if (family == AF_INET) {
        // Load protocol and address
        bpf_probe_read(&evt.l4proto, member_size(struct iphdr, protocol),  first->head + iphdroffset + offsetof(struct iphdr, protocol));
        bpf_probe_read(evt.saddr,    member_size(struct iphdr, saddr),     first->head + iphdroffset + offsetof(struct iphdr, saddr));
        bpf_probe_read(evt.daddr,    member_size(struct iphdr, daddr),     first->head + iphdroffset + offsetof(struct iphdr, daddr));

        // Load constants
        proto_icmp = IPPROTO_ICMP;
        proto_icmp_echo_request = ICMP_ECHO;
        proto_icmp_echo_reply   = ICMP_ECHOREPLY;
    } else if (family == AF_INET6) {
        // Load protocol and address
        bpf_probe_read(&evt.l4proto, member_size(struct ipv6hdr, nexthdr),  first->head + iphdroffset + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(evt.saddr,    member_size(struct ipv6hdr, saddr),    first->head + iphdroffset + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(evt.daddr,    member_size(struct ipv6hdr, daddr),    first->head + iphdroffset + offsetof(struct ipv6hdr, daddr));

        // Load constants
        proto_icmp = IPPROTO_ICMPV6;
        proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
        proto_icmp_echo_reply   = ICMPV6_ECHO_REPLY;
    } else {
        return 0;
    }

    // Filter ICMP packets
    if (evt.l4proto != proto_icmp) {
        return 0;
    }

    // Filter ICMP echo request and echo reply
    struct icmphdr icmphdr;
    bpf_probe_read(&icmphdr, sizeof(struct icmphdr), first->head + icmphdroffset);
    if (icmphdr.type != proto_icmp_echo_request && icmphdr.type != proto_icmp_echo_reply) {
        return 0;
    }
    evt.icmptype = icmphdr.type;
    evt.icmpid   = be16_to_cpu(icmphdr.un.echo.id);
    evt.icmpseq  = be16_to_cpu(icmphdr.un.echo.sequence);

    // Get netns id
#ifdef CONFIG_NET_NS
    evt.netns = sk->__sk_common.skc_net.net->ns.inum;
#else
    evt.netns = 0;
#endif

    // Get interface name
    __builtin_memcpy(&evt.ifname, dev->name, IFNAMSIZ);

    // Send event to userland
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
};

'''

TASK_COMM_LEN = 16 # linux/sched.h
IFNAMSIZ      = 16 # uapi/linux/if.h

class RouteEvt(ct.Structure):
    _fields_ = [
        # Routing information
        ("comm",    ct.c_char * TASK_COMM_LEN),
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("proto",    ct.c_ulonglong),
        ("l4proto",  ct.c_ulonglong),
        ("icmptype", ct.c_ulonglong),
        ("icmpid",   ct.c_ulonglong),
        ("icmpseq",  ct.c_ulonglong),
        ("saddr",    ct.c_ulonglong * 2),
        ("daddr",    ct.c_ulonglong * 2),
    ]

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(RouteEvt)).contents

    proto_family = event.proto & 0xff
    proto_type = event.proto >> 16 & 0xff

    saddr = ""
    daddr = ""
    if proto_type == AF_INET:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    elif proto_type == AF_INET6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)

    # Print event
    print "[%12s] %16s ping#%05u.%03u %s -> %s" % (event.netns, event.ifname, event.icmpid, event.icmpseq, saddr, daddr)

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_evt"].open_perf_buffer(event_printer)

    while True:
        b.kprobe_poll()
