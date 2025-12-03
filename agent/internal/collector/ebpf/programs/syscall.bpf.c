#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define TASK_COMM_LEN 16

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU ((__u64)-1)
#endif

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct event {
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 event_type;
	__u32 aux;
	char comm[TASK_COMM_LEN];
};

struct event_stats {
	__u64 emitted;
	__u64 errors;
	__u64 dropped;
	__s64 last_errno;
};

static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static int (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static int (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data,
				    __u64 size) = (void *)BPF_FUNC_perf_event_output;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;

enum {
	EVENT_TYPE_EXEC = 1,
	EVENT_TYPE_EXIT = 2,
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 0,
};

struct bpf_map_def SEC("maps") event_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event_stats),
	.max_entries = 1,
};

static __inline void record_result(int rc)
{
	const __u32 key = 0;
	struct event_stats *stats = bpf_map_lookup_elem(&event_stats, &key);

	if (!stats)
		return;
	if (rc == 0) {
		stats->emitted++;
		return;
	}
	stats->errors++;
	stats->last_errno = rc;
	if (rc == -EAGAIN || rc == -ENOSPC)
		stats->dropped++;
}

static __inline int submit_event(void *ctx, __u32 event_type, __u32 aux)
{
	struct event evt = {};
	__u64 pid_tgid;

	evt.timestamp = bpf_ktime_get_ns();
	pid_tgid = bpf_get_current_pid_tgid();
	evt.pid = pid_tgid >> 32;
	evt.tgid = pid_tgid & 0xffffffff;
	evt.event_type = event_type;
	evt.aux = aux;
	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

	int rc = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

	record_result(rc);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(void *ctx)
{
	return submit_event(ctx, EVENT_TYPE_EXEC, 0);
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(void *ctx)
{
	return submit_event(ctx, EVENT_TYPE_EXIT, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
