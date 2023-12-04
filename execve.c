#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "execve.h"
#include "execve.skel.h"

struct execve_bpf *skel;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level >= LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct data_t *proc = data;
    printf("User %d %s (PID %d): %s %s %s %s %s %s %s %s\n", proc->uid, proc->command, proc->pid, proc->argv[0], proc->argv[1], proc->argv[2], proc->argv[3], proc->argv[4], proc->argv[5], proc->argv[6], proc->argv[7]);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
    printf("lost event\n");
}

int main()
{
    // struct bpf_object_open_opts *o;
    int err;
    struct perf_buffer *pb = NULL;

    libbpf_set_print(libbpf_print_fn);

    char log_buf[64 * 1024];
    LIBBPF_OPTS(bpf_object_open_opts, opts,
                .kernel_log_buf = log_buf,
                .kernel_log_size = sizeof(log_buf),
                .kernel_log_level = 1, );

    skel = execve_bpf__open_opts(&opts);
    if (!skel)
    {
        printf("Failed to open BPF object\n");
        return 1;
    }

    err = execve_bpf__load(skel);
    // Print the verifier log
    for (int i = 0; i < sizeof(log_buf); i++)
    {
        if (log_buf[i] == 0 && log_buf[i + 1] == 0)
        {
            break;
        }
        printf("%c", log_buf[i]);
    }

    if (err)
    {
        printf("Failed to load BPF object\n");
        goto cleanup;
    }

    // Attach the progams to the events
    err = execve_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
    if (!pb)
    {
        goto cleanup;
    }

    while (true)
    {
        err = perf_buffer__poll(pb, 100 /* timeout, ms */);
        // Ctrl-C gives -EINTR
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);
    goto cleanup;

    cleanup:
        execve_bpf__destroy(skel);
        return -err;
}
