from bcc import BPF
import ctypes as ct

bpf_text = '''
#include <net/inet_sock.h>
#include <bcc/proto.h>

// Event structure
struct route_evt_t {
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(route_evt);

int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog)
{
    // Built event for userland
    struct route_evt_t evt = {};
    bpf_get_current_comm(evt.comm, TASK_COMM_LEN);

    // Send event to userland
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
};

'''

TASK_COMM_LEN = 16 # linux/sched.h
class RouteEvt(ct.Structure):
    _fields_ = [
        ("comm",  ct.c_char * TASK_COMM_LEN),
    ]

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(RouteEvt)).contents

    # Print event
    print event.comm

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_evt"].open_perf_buffer(event_printer)

    while True:
        b.kprobe_poll()
