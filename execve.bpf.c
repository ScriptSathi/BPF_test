#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "execve.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

// FROM /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
// name: sys_enter_execve
// ID: 622
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:const char * filename;    offset:16;      size:8; signed:0;
//         field:const char *const * argv; offset:24;      size:8; signed:0;
//         field:const char *const * envp; offset:32;      size:8; signed:0;
struct syscalls_enter_execve
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    void *filename_ptr;
    char **argv;
    long envp;
};

SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct syscalls_enter_execve *ctx)
{
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), ctx->filename_ptr);


    for (int i = 0; i < sizeof(ctx->argv); i++)
    {
        char *tmp;
        bpf_probe_read(&tmp, sizeof(tmp), &ctx->argv[i]);
        bpf_probe_read_str(data.argv[i], sizeof(data.argv[i]), tmp);
        bpf_printk("arg%d: %s ", i, data.argv[i]);
    }

    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
