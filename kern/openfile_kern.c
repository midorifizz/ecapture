#include "ecapture.h"

struct open_event {
    u64 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[20];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct open_event);
    __uint(max_entries, 1024);
} open_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} open_events SEC(".maps");


SEC("kprobe/do_sys_open")
int kprobe_do_sys_open(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct open_event event = {};
	event.pid = pid;
	event.timestamp = bpf_ktime_get_ns();

	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	const char *fp = (char *)PT_REGS_PARM2(ctx);
	bpf_probe_read(&event.filename, 20, (void *)PT_REGS_PARM2(ctx));

	bpf_perf_event_output(ctx, &open_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
