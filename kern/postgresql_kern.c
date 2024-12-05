#include "ecapture.h"

struct PostgreSQLEvent {
    u64 pid;
    u64 timestamp;
    u32 event_type;

    u32 object;           // typedef unsigned int Oid;
    int mode;             // typedef int LOCKMODE;
    u32 requested;        // Requested locks
    s64 lock_local_hold;  // Requested local locks

    char payload_str1[127];  // Generic payload string data 1 (e.g., a query / a schema)
    char payload_str2[127];  // Generic payload string data 2 (e.g., a table)

    int stackid;  // The id of the stack
};

// 定义 perf ring buffer，用于传递事件
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} lockevents SEC(".maps");

static __always_inline void fill_basic_data(struct PostgreSQLEvent *event) {
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
}

SEC("uprobe/table_open")
int bpf_table_open(struct pt_regs *ctx) {
    struct PostgreSQLEvent event = { .event_type = 37 /* TABLE_OPEN */ };

    // 参数 1: 读取 relationId
    u32 object = (u32)PT_REGS_PARM1(ctx);
    event.object = object;

    // 参数 2: 读取 lockmode
    int lockmode = (int)PT_REGS_PARM2(ctx);
    event.mode = lockmode;

    fill_basic_data(&event);

    bpf_perf_event_output(ctx, &lockevents, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
