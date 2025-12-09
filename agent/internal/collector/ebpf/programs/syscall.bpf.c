#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/uio.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define TASK_COMM_LEN 16
#define EVENT_DATA_LEN 64
#define DATA_KIND_NONE 0
#define DATA_KIND_STRING 1
#define DATA_KIND_IPV6 2
#define DATA_KIND_BINARY 3
#define ADDR_TAG_UNIX 1
#define ADDR_TAG_IPV6 2

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
	__u32 uid;
	__u32 gid;
	__u64 cgroup_id;
	__u32 event_type;
	__u32 aux;
	char comm[TASK_COMM_LEN];
	char data[EVENT_DATA_LEN];
	__u32 data_len;
	__u32 data_kind;
	__u32 extra0;
	__u32 extra1;
	__u32 extra2;
	__u32 extra3;
};

struct event_stats {
	__u64 emitted;
	__u64 errors;
	__u64 dropped;
	__s64 last_errno;
};

struct rename_payload {
	char old_path[EVENT_DATA_LEN / 2];
	char new_path[EVENT_DATA_LEN / 2];
};

struct memory_payload {
	__u64 addr;
	__u64 len;
	__u64 prot;
	__u64 flags;
	__s64 fd;
	__u64 offset;
};

static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static int (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static int (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data,
				    __u64 size) = (void *)BPF_FUNC_perf_event_output;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_probe_read_user_str)(void *dst, __u32 size,
			      const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_user_str;
static int (*bpf_probe_read_user)(void *dst, __u32 size,
			  const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_user;

enum {
	EVENT_TYPE_EXEC = 1,
	EVENT_TYPE_EXIT = 2,
	EVENT_TYPE_CLONE = 3,
	EVENT_TYPE_OPEN = 10,
	EVENT_TYPE_WRITE = 11,
	EVENT_TYPE_UNLINK = 12,
	EVENT_TYPE_RENAME = 13,
	EVENT_TYPE_SOCKET = 20,
	EVENT_TYPE_CONNECT = 21,
	EVENT_TYPE_SENDMSG = 22,
	EVENT_TYPE_MMAP = 30,
	EVENT_TYPE_MPROTECT = 31,
	EVENT_TYPE_MUNMAP = 32,
};

#ifndef MODULE_PROCESS
#define MODULE_PROCESS 1
#endif
#ifndef MODULE_FILESYSTEM
#define MODULE_FILESYSTEM 1
#endif
#ifndef MODULE_NETWORK
#define MODULE_NETWORK 1
#endif
#ifndef MODULE_MEMORY
#define MODULE_MEMORY 1
#endif

struct trace_event_raw_sys_enter {
	__u64 unused;
	long id;
	unsigned long args[6];
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

static __inline int submit_event_with_payload(void *ctx, __u32 event_type, __u32 aux,
					      const void *data_ptr, __u32 data_len,
					      __u32 data_kind, __u32 extra0, __u32 extra1,
					      __u32 extra2, __u32 extra3)
{
static __inline void init_event(struct event *evt, __u32 event_type, __u32 aux)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	evt->timestamp = bpf_ktime_get_ns();
	evt->pid = pid_tgid >> 32;
	evt->tgid = pid_tgid & 0xffffffff;
	evt->uid = uid_gid & 0xffffffff;
	evt->gid = uid_gid >> 32;
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->event_type = event_type;
	evt->aux = aux;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

static __inline int submit_event_with_payload(void *ctx, __u32 event_type, __u32 aux,
					      const void *data_ptr, __u32 data_len,
					      __u32 data_kind, __u32 extra0, __u32 extra1,
					      __u32 extra2, __u32 extra3)
{
	struct event evt = {};

	init_event(&evt, event_type, aux);
	if (data_ptr) {
		if (data_kind == DATA_KIND_STRING || data_len == 0) {
			bpf_probe_read_user_str(&evt.data, sizeof(evt.data), data_ptr);
			evt.data_kind = DATA_KIND_STRING;
		} else {
			__u32 len = data_len;
			if (len == 0 || len > EVENT_DATA_LEN) {
				len = EVENT_DATA_LEN;
			}
			bpf_probe_read_user(&evt.data, len, data_ptr);
			evt.data_len = len;
			evt.data_kind = data_kind;
		}
	}
	evt.extra0 = extra0;
	evt.extra1 = extra1;
	evt.extra2 = extra2;
	evt.extra3 = extra3;

	int rc = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

	record_result(rc);
	return 0;
}

static __inline int submit_event_with_kernel_payload(void *ctx, __u32 event_type, __u32 aux,
						     const void *data_ptr, __u32 data_len,
						     __u32 extra0, __u32 extra1, __u32 extra2,
						     __u32 extra3)
{
	struct event evt = {};

	init_event(&evt, event_type, aux);
	if (data_ptr && data_len > 0) {
		__u32 len = data_len;
		if (len > EVENT_DATA_LEN) {
			len = EVENT_DATA_LEN;
		}
		__builtin_memcpy(&evt.data, data_ptr, len);
		evt.data_len = len;
		evt.data_kind = DATA_KIND_BINARY;
	}
	evt.extra0 = extra0;
	evt.extra1 = extra1;
	evt.extra2 = extra2;
	evt.extra3 = extra3;

	int rc = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	record_result(rc);
	return 0;
}

static __inline int submit_event(void *ctx, __u32 event_type, __u32 aux)
{
	return submit_event_with_payload(ctx, event_type, aux, 0, 0, DATA_KIND_NONE, 0, 0, 0, 0);
}

#if MODULE_PROCESS
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[0];
	return submit_event_with_payload(ctx, EVENT_TYPE_EXEC, 0, filename, 0, DATA_KIND_STRING, 0, 0, 0, 0);
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(void *ctx)
{
	return submit_event(ctx, EVENT_TYPE_EXIT, 0);
}

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_sys_enter_clone(struct trace_event_raw_sys_enter *ctx)
{
	__u32 flags = (__u32)ctx->args[0];
	return submit_event_with_payload(ctx, EVENT_TYPE_CLONE, flags, 0, 0, DATA_KIND_NONE, flags, 0, 0, 0);
}
#endif

#if MODULE_FILESYSTEM
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	__s32 dirfd = (__s32)ctx->args[0];
	const char *filename = (const char *)ctx->args[1];
	__u32 flags = (__u32)ctx->args[2];
	__u32 mode = (__u32)ctx->args[3];
	return submit_event_with_payload(ctx, EVENT_TYPE_OPEN, (__u32)dirfd, filename, 0, DATA_KIND_STRING,
					 flags, mode, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	__s32 fd = (__s32)ctx->args[0];
	__u32 count = (__u32)ctx->args[2];
	return submit_event_with_payload(ctx, EVENT_TYPE_WRITE, (__u32)fd, 0, 0, DATA_KIND_NONE, (__u32)fd,
					 count, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	__s32 dirfd = (__s32)ctx->args[0];
	const char *filename = (const char *)ctx->args[1];
	return submit_event_with_payload(ctx, EVENT_TYPE_UNLINK, (__u32)dirfd, filename, 0, DATA_KIND_STRING,
					 0, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_sys_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
	const char *old_path = (const char *)ctx->args[1];
	const char *new_path = (const char *)ctx->args[3];
	struct rename_payload payload = {};
	if (old_path) {
		bpf_probe_read_user_str(&payload.old_path, sizeof(payload.old_path), old_path);
	}
	if (new_path) {
		bpf_probe_read_user_str(&payload.new_path, sizeof(payload.new_path), new_path);
	}
	return submit_event_with_kernel_payload(ctx, EVENT_TYPE_RENAME, 0, &payload, sizeof(payload),
						(__u32)ctx->args[0], (__u32)ctx->args[2], 0, 0);
}
#endif

#if MODULE_NETWORK
SEC("tracepoint/syscalls/sys_enter_socket")
int handle_sys_enter_socket(struct trace_event_raw_sys_enter *ctx)
{
	__u32 family = (__u32)ctx->args[0];
	__u32 type = (__u32)ctx->args[1];
	__u32 protocol = (__u32)ctx->args[2];
	return submit_event_with_payload(ctx, EVENT_TYPE_SOCKET, 0, 0, 0, DATA_KIND_NONE, family, type, protocol, 0);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	__s32 fd = (__s32)ctx->args[0];
	__u32 family = 0;
	__u32 port = 0;
	__u32 addr_v4 = 0;
	__u32 addr_tag = 0;
	const void *sockaddr_ptr = (const void *)ctx->args[1];
	const void *payload = 0;
	__u32 data_kind = DATA_KIND_NONE;
	__u32 data_len = 0;
	int addrlen = (int)ctx->args[2];

	if (sockaddr_ptr && addrlen >= (int)sizeof(struct sockaddr)) {
		struct sockaddr sa = {};
		bpf_probe_read_user(&sa, sizeof(sa), sockaddr_ptr);
		family = sa.sa_family;
		if (family == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
			struct sockaddr_in sin = {};
			bpf_probe_read_user(&sin, sizeof(sin), sockaddr_ptr);
			port = (__u32)__builtin_bswap16(sin.sin_port);
			addr_v4 = sin.sin_addr.s_addr;
		} else if (family == AF_UNIX && addrlen >= (int)sizeof(struct sockaddr_un)) {
			const struct sockaddr_un *sun_ptr = (const struct sockaddr_un *)sockaddr_ptr;
			payload = (const void *)sun_ptr->sun_path;
			data_kind = DATA_KIND_STRING;
			addr_tag = ADDR_TAG_UNIX;
		} else if (family == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
			struct sockaddr_in6 sin6 = {};
			bpf_probe_read_user(&sin6, sizeof(sin6), sockaddr_ptr);
			port = (__u32)__builtin_bswap16(sin6.sin6_port);
			const struct sockaddr_in6 *sin6_ptr = (const struct sockaddr_in6 *)sockaddr_ptr;
			payload = (const void *)&sin6_ptr->sin6_addr;
			data_kind = DATA_KIND_IPV6;
			data_len = sizeof(sin6.sin6_addr);
			addr_tag = ADDR_TAG_IPV6;
		}
	}
	return submit_event_with_payload(ctx, EVENT_TYPE_CONNECT, (__u32)fd, payload, data_len, data_kind,
					 family, port, addr_v4, addr_tag);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int handle_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
	__s32 fd = (__s32)ctx->args[0];
	__u32 family = 0;
	__u32 port = 0;
	__u32 addr_v4 = 0;
	__u32 addr_tag = 0;
	const struct user_msghdr *msghdr_ptr = (const struct user_msghdr *)ctx->args[1];
	const void *payload = 0;
	__u32 data_kind = DATA_KIND_NONE;
	__u32 data_len = 0;

	if (msghdr_ptr) {
		struct user_msghdr hdr = {};
		bpf_probe_read_user(&hdr, sizeof(hdr), msghdr_ptr);
		if (hdr.msg_name && hdr.msg_namelen >= sizeof(struct sockaddr)) {
			struct sockaddr sa = {};
			bpf_probe_read_user(&sa, sizeof(sa), hdr.msg_name);
			family = sa.sa_family;
			if (family == AF_INET && hdr.msg_namelen >= sizeof(struct sockaddr_in)) {
				struct sockaddr_in sin = {};
				bpf_probe_read_user(&sin, sizeof(sin), hdr.msg_name);
				port = (__u32)__builtin_bswap16(sin.sin_port);
				addr_v4 = sin.sin_addr.s_addr;
			} else if (family == AF_UNIX && hdr.msg_namelen >= sizeof(struct sockaddr_un)) {
				const struct sockaddr_un *sun_ptr = (const struct sockaddr_un *)hdr.msg_name;
				payload = (const void *)sun_ptr->sun_path;
				data_kind = DATA_KIND_STRING;
				addr_tag = ADDR_TAG_UNIX;
			} else if (family == AF_INET6 && hdr.msg_namelen >= sizeof(struct sockaddr_in6)) {
				struct sockaddr_in6 sin6 = {};
				bpf_probe_read_user(&sin6, sizeof(sin6), hdr.msg_name);
				port = (__u32)__builtin_bswap16(sin6.sin6_port);
				const struct sockaddr_in6 *sin6_ptr = (const struct sockaddr_in6 *)hdr.msg_name;
				payload = (const void *)&sin6_ptr->sin6_addr;
				data_kind = DATA_KIND_IPV6;
				data_len = sizeof(sin6.sin6_addr);
				addr_tag = ADDR_TAG_IPV6;
			}
		}
	}
	return submit_event_with_payload(ctx, EVENT_TYPE_SENDMSG, (__u32)fd, payload, data_len, data_kind,
					 family, port, addr_v4, addr_tag);
}
#endif

#if MODULE_MEMORY
SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
	struct memory_payload payload = {};
	payload.addr = (__u64)ctx->args[0];
	payload.len = (__u64)ctx->args[1];
	payload.prot = (__u64)ctx->args[2];
	payload.flags = (__u64)ctx->args[3];
	payload.fd = (__s64)ctx->args[4];
	payload.offset = (__u64)ctx->args[5];
	return submit_event_with_kernel_payload(ctx, EVENT_TYPE_MMAP, 0, &payload, sizeof(payload), 0, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int handle_sys_enter_mprotect(struct trace_event_raw_sys_enter *ctx)
{
	struct memory_payload payload = {};
	payload.addr = (__u64)ctx->args[0];
	payload.len = (__u64)ctx->args[1];
	payload.prot = (__u64)ctx->args[2];
	return submit_event_with_kernel_payload(ctx, EVENT_TYPE_MPROTECT, 0, &payload, sizeof(payload), 0, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int handle_sys_enter_munmap(struct trace_event_raw_sys_enter *ctx)
{
	struct memory_payload payload = {};
	payload.addr = (__u64)ctx->args[0];
	payload.len = (__u64)ctx->args[1];
	return submit_event_with_kernel_payload(ctx, EVENT_TYPE_MUNMAP, 0, &payload, sizeof(payload), 0, 0, 0, 0);
}
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";
