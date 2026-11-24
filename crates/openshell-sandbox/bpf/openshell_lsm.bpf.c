// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Boot-once BPF LSM for privileged (true guest root) VM sandboxes.
//
// Enforces three planes inside a hardened Linux 6.12+ VM kernel:
// 1. Shim seal: protects openshell-sandbox (guest PID 1 + launcher), its
//    /run/openshell superblock, its freezer cgroup, AF_VSOCK, init_net, and
//    the bpf() syscall itself against guest UID 0.
// 2. Workload filesystem_policy: enforces read-only / read-write / denied
//    inode ancestry rules and blocks read-write remount / shadow bypasses,
//    supporting live map reload from the sealed shim.
// 3. Workload process rules & telemetry: checks bprm_check_security against
//    process rules, tracks task lineage in BPF_MAP_TYPE_TASK_STORAGE, and
//    streams kernel-sourced events over a BPF ringbuf.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;
typedef int pid_t;
typedef __u32 dev_t;
typedef __u16 umode_t;

#define EPERM 1
#define EACCES 13
#define AF_UNIX 1
#define AF_VSOCK 40
#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_CREAT 00000100
#define O_TRUNC 00001000
#define O_APPEND 00002000
#define MS_RDONLY 1UL
#define MS_REMOUNT 32UL
#define CLONE_THREAD 0x00010000UL
#define CGROUP2_SUPER_MAGIC 0x63677270UL

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_LOCAL_STORAGE_GET_F_CREATE (1ULL << 0)

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __always_inline inline __attribute__((always_inline))

// Minimal CO-RE kernel struct definitions (relocated against /sys/kernel/btf/vmlinux).
struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct nsproxy {
    struct net *net_ns;
} __attribute__((preserve_access_index));

struct task_struct {
    pid_t pid;
    pid_t tgid;
    struct task_struct *real_parent;
    struct task_struct *group_leader;
    struct nsproxy *nsproxy;
} __attribute__((preserve_access_index));

struct super_block {
    dev_t s_dev;
    unsigned long s_magic;
} __attribute__((preserve_access_index));

struct inode {
    umode_t i_mode;
    struct super_block *i_sb;
    unsigned long i_ino;
} __attribute__((preserve_access_index));

struct dentry {
    struct dentry *d_parent;
    struct inode *d_inode;
    struct super_block *d_sb;
} __attribute__((preserve_access_index));

struct vfsmount {
    struct super_block *mnt_sb;
} __attribute__((preserve_access_index));

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    struct inode *f_inode;
    unsigned int f_flags;
} __attribute__((preserve_access_index));

struct linux_binprm {
    struct file *file;
} __attribute__((preserve_access_index));

// BPF helpers (stable Linux UAPI helper IDs).
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
static struct task_struct *(*bpf_get_current_task_btf)(void) = (void *)158;
static void *(*bpf_task_storage_get)(void *map, struct task_struct *task, void *value, __u64 flags) = (void *)156;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

#define CORE_READ(dst, ptr, field) \
    bpf_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(ptr)->field))

// Frozen seal configuration populated once at startup before workload launch.
struct seal_config {
    __u32 active;
    __u32 shim_tgid;
    __u32 launcher_tgid;
    __u32 runtime_sb_dev;
    __u32 runtime_root_dev;
    __u32 init_net_inum;
    __u64 freezer_cgroup_ino;
    __u32 cgroup_sb_dev;
    __u32 guest_parent_tgid;
};

// Live-reloadable policy flags updated only by the sealed shim.
struct policy_config {
    __u32 fs_enabled;
    __u32 proc_enabled;
    __u32 proc_default_deny;
    __u32 _pad;
};

struct inode_key {
    __u32 dev;
    __u32 _pad;
    __u64 ino;
};

// Filesystem rule verdicts.
#define FS_RULE_RW 1U
#define FS_RULE_RO 2U
#define FS_RULE_DENY 3U

// Process rule verdicts.
#define PROC_RULE_ALLOW 1U
#define PROC_RULE_DENY 2U

// Task lineage stored in BPF_MAP_TYPE_TASK_STORAGE.
struct task_lineage {
    __u32 tgid;
    __u32 parent_tgid;
    __u32 flags;
    __u32 _pad;
};

#define TASK_FLAG_SHIM 1U
#define TASK_FLAG_WORKLOAD 2U

// Telemetry event types streamed over telemetry_rb.
#define EVT_EXEC 1U
#define EVT_DENY_SEAL 2U
#define EVT_DENY_FS 3U
#define EVT_DENY_PROC 4U
#define EVT_TASK_EXIT 5U

// Seal denial sub-reasons.
#define SEAL_REASON_BPF 1U
#define SEAL_REASON_PTRACE 2U
#define SEAL_REASON_PERF 3U
#define SEAL_REASON_KILL 4U
#define SEAL_REASON_RLIMIT 5U
#define SEAL_REASON_VSOCK 6U
#define SEAL_REASON_INIT_NET 7U
#define SEAL_REASON_RUNTIME_FS 8U
#define SEAL_REASON_FREEZER 9U
#define SEAL_REASON_MOUNT 10U
#define SEAL_REASON_LOCKDOWN 11U

struct telemetry_event {
    __u32 event_type;
    __u32 reason;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 dev;
    __u32 _pad;
    __u64 ino;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct seal_config);
} seal_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} shim_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_config);
} policy_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct inode_key);
    __type(value, __u32);
} fs_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct inode_key);
    __type(value, __u32);
} proc_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_lineage);
} task_meta SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} telemetry_rb SEC(".maps");

static __always_inline const struct seal_config *get_seal_cfg(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&seal_cfg, &zero);
}

static __always_inline const struct policy_config *get_policy_cfg(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&policy_cfg, &zero);
}

static __always_inline int is_shim_tgid(const struct seal_config *cfg, __u32 tgid) {
    if (!cfg || tgid == 0) {
        return 0;
    }
    return tgid == cfg->shim_tgid || (cfg->launcher_tgid != 0 && tgid == cfg->launcher_tgid);
}

static __always_inline int current_is_shim(const struct seal_config *cfg) {
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    return is_shim_tgid(cfg, tgid);
}

// Guest root-PID-namespace init (e.g. kata-agent in a Kata Containers VM,
// where openshell-sandbox runs in a child container with shim_tgid > 1) is
// part of the VM TCB and owns container teardown (SIGTERM/SIGKILL, vsock
// ttrpc, and rootfs unmount). No workload process can ever have root tgid == 1.
static __always_inline int current_is_guest_init(const struct seal_config *cfg) {
    if (!cfg || cfg->shim_tgid <= 1) {
        return 0;
    }
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    return tgid == 1 || (cfg->guest_parent_tgid != 0 && tgid == cfg->guest_parent_tgid);
}

static __always_inline int current_is_shim_or_guest_init(const struct seal_config *cfg) {
    return current_is_shim(cfg) || current_is_guest_init(cfg);
}

static __always_inline int task_is_shim(const struct seal_config *cfg, struct task_struct *task) {
    if (!cfg || !task) {
        return 0;
    }
    pid_t tgid = 0;
    CORE_READ(tgid, task, tgid);
    return is_shim_tgid(cfg, (__u32)tgid);
}

static __always_inline __u32 current_parent_tgid(void) {
    struct task_struct *cur = bpf_get_current_task_btf();
    if (!cur) {
        return 0;
    }
    struct task_lineage *meta = bpf_task_storage_get(&task_meta, cur, 0, 0);
    if (meta && meta->parent_tgid != 0) {
        return meta->parent_tgid;
    }
    struct task_struct *parent = 0;
    CORE_READ(parent, cur, real_parent);
    if (!parent) {
        return 0;
    }
    pid_t ptgid = 0;
    CORE_READ(ptgid, parent, tgid);
    return (__u32)ptgid;
}

static __always_inline void emit_event(__u32 event_type, __u32 reason, __u32 dev, __u64 ino) {
    struct telemetry_event *evt = bpf_ringbuf_reserve(&telemetry_rb, sizeof(*evt), 0);
    if (!evt) {
        return;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->event_type = event_type;
    evt->reason = reason;
    evt->pid = (__u32)pid_tgid;
    evt->tgid = (__u32)(pid_tgid >> 32);
    evt->ppid = current_parent_tgid();
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->dev = dev;
    evt->_pad = 0;
    evt->ino = ino;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);
}

static __always_inline __u32 current_net_inum(void) {
    struct task_struct *cur = bpf_get_current_task_btf();
    if (!cur) {
        return 0;
    }
    struct nsproxy *nsp = 0;
    CORE_READ(nsp, cur, nsproxy);
    if (!nsp) {
        return 0;
    }
    struct net *net_ns = 0;
    CORE_READ(net_ns, nsp, net_ns);
    if (!net_ns) {
        return 0;
    }
    unsigned int inum = 0;
    CORE_READ(inum, net_ns, ns.inum);
    return (__u32)inum;
}

// Check if a dentry belongs to the runtime superblocks or protected freezer cgroup.
static __always_inline int is_protected_runtime_dentry(
    const struct seal_config *cfg,
    struct dentry *dentry,
    int is_write,
    __u32 *out_dev,
    __u64 *out_ino
) {
    if (!cfg || !dentry) {
        return 0;
    }
    struct super_block *sb = 0;
    CORE_READ(sb, dentry, d_sb);
    if (!sb) {
        return 0;
    }
    dev_t s_dev = 0;
    unsigned long s_magic = 0;
    CORE_READ(s_dev, sb, s_dev);
    CORE_READ(s_magic, sb, s_magic);
    *out_dev = (__u32)s_dev;

    struct inode *inode = 0;
    CORE_READ(inode, dentry, d_inode);
    unsigned long ino = 0;
    if (inode) {
        CORE_READ(ino, inode, i_ino);
    }
    *out_ino = (__u64)ino;

    if (is_write && ((cfg->runtime_sb_dev != 0 && s_dev == cfg->runtime_sb_dev) ||
                     (cfg->runtime_root_dev != 0 && s_dev == cfg->runtime_root_dev))) {
        return SEAL_REASON_RUNTIME_FS;
    }

    // Protect the runtime-owned workload freezer cgroup directory (and its
    // control files such as cgroup.freeze) from any write by unmarked tasks.
    if (is_write && cfg->freezer_cgroup_ino != 0 && s_magic == CGROUP2_SUPER_MAGIC) {
        struct dentry *cur = dentry;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (!cur) {
                break;
            }
            struct inode *ci = 0;
            CORE_READ(ci, cur, d_inode);
            if (ci) {
                unsigned long cino = 0;
                CORE_READ(cino, ci, i_ino);
                if (cino == cfg->freezer_cgroup_ino) {
                    return SEAL_REASON_FREEZER;
                }
            }
            struct dentry *parent = 0;
            CORE_READ(parent, cur, d_parent);
            if (!parent || parent == cur) {
                break;
            }
            cur = parent;
        }
    }
    return 0;
}

// Walk dentry->d_parent up to 24 levels looking for the most-specific fs_rules entry.
static __always_inline __u32 lookup_fs_rule(struct dentry *dentry, __u32 *matched_dev, __u64 *matched_ino) {
    if (!dentry) {
        return 0;
    }
    struct super_block *sb = 0;
    CORE_READ(sb, dentry, d_sb);
    if (!sb) {
        return 0;
    }
    dev_t s_dev = 0;
    CORE_READ(s_dev, sb, s_dev);

    struct dentry *cur = dentry;
    for (int i = 0; i < 24; i++) {
        if (!cur) {
            break;
        }
        struct inode *ci = 0;
        CORE_READ(ci, cur, d_inode);
        if (ci) {
            unsigned long cino = 0;
            CORE_READ(cino, ci, i_ino);
            struct inode_key key = {
                .dev = (__u32)s_dev,
                ._pad = 0,
                .ino = (__u64)cino,
            };
            __u32 *rule = bpf_map_lookup_elem(&fs_rules, &key);
            if (rule) {
                *matched_dev = key.dev;
                *matched_ino = key.ino;
                return *rule;
            }
        }
        struct dentry *parent = 0;
        CORE_READ(parent, cur, d_parent);
        if (!parent || parent == cur) {
            break;
        }
        cur = parent;
    }
    return 0;
}

static __always_inline int check_dentry_access(struct dentry *dentry, int is_write) {
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim_or_guest_init(cfg)) {
        return 0;
    }
    __u32 dev = 0;
    __u64 ino = 0;
    int seal_reason = is_protected_runtime_dentry(cfg, dentry, is_write, &dev, &ino);
    if (seal_reason != 0) {
        emit_event(EVT_DENY_SEAL, (__u32)seal_reason, dev, ino);
        return -EPERM;
    }

    const struct policy_config *pcfg = get_policy_cfg();
    if (!pcfg || !pcfg->fs_enabled) {
        return 0;
    }
    __u32 mdev = dev;
    __u64 mino = ino;
    __u32 rule = lookup_fs_rule(dentry, &mdev, &mino);
    if (rule == FS_RULE_DENY) {
        emit_event(EVT_DENY_FS, rule, mdev, mino);
        return -EACCES;
    }
    if (is_write && rule == FS_RULE_RO) {
        emit_event(EVT_DENY_FS, rule, mdev, mino);
        return -EACCES;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Plane 1: Shim seal hooks
// ---------------------------------------------------------------------------

SEC("lsm/bpf")
int openshell_lsm_bpf(unsigned long long *ctx) {
    int ret = (int)ctx[3];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active) {
        __u32 k0 = 0;
        __u32 *recorded = bpf_map_lookup_elem(&shim_id, &k0);
        if (recorded && *recorded == 0) {
            *recorded = (__u32)(bpf_get_current_pid_tgid() >> 32);
        }
        __u32 k1 = 1;
        __u32 *rec_parent = bpf_map_lookup_elem(&shim_id, &k1);
        if (rec_parent && *rec_parent == 0) {
            struct task_struct *cur = bpf_get_current_task_btf();
            if (cur) {
                struct task_struct *parent = 0;
                CORE_READ(parent, cur, real_parent);
                if (parent) {
                    pid_t ptgid = 0;
                    CORE_READ(ptgid, parent, tgid);
                    if (ptgid > 0) {
                        *rec_parent = (__u32)ptgid;
                    }
                }
            }
        }
        return 0;
    }
    if (current_is_shim(cfg)) {
        return 0;
    }
    emit_event(EVT_DENY_SEAL, SEAL_REASON_BPF, 0, (__u64)ctx[0]);
    return -EPERM;
}

SEC("lsm/ptrace_access_check")
int openshell_lsm_ptrace(unsigned long long *ctx) {
    int ret = (int)ctx[2];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim(cfg)) {
        return 0;
    }
    struct task_struct *child = (struct task_struct *)ctx[0];
    if (task_is_shim(cfg, child)) {
        emit_event(EVT_DENY_SEAL, SEAL_REASON_PTRACE, 0, (__u64)ctx[1]);
        return -EACCES;
    }
    return 0;
}

SEC("lsm/perf_event_alloc")
int openshell_lsm_perf(unsigned long long *ctx) {
    int ret = (int)ctx[1];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim(cfg)) {
        return 0;
    }
    emit_event(EVT_DENY_SEAL, SEAL_REASON_PERF, 0, 0);
    return -EACCES;
}

SEC("lsm/task_kill")
int openshell_lsm_task_kill(unsigned long long *ctx) {
    int ret = (int)ctx[4];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim_or_guest_init(cfg)) {
        return 0;
    }
    struct task_struct *target = (struct task_struct *)ctx[0];
    if (task_is_shim(cfg, target)) {
        emit_event(EVT_DENY_SEAL, SEAL_REASON_KILL, 0, (__u64)ctx[2]);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/task_setrlimit")
int openshell_lsm_task_setrlimit(unsigned long long *ctx) {
    int ret = (int)ctx[3];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim(cfg)) {
        return 0;
    }
    struct task_struct *target = (struct task_struct *)ctx[0];
    if (task_is_shim(cfg, target)) {
        emit_event(EVT_DENY_SEAL, SEAL_REASON_RLIMIT, 0, (__u64)ctx[1]);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/socket_create")
int openshell_lsm_socket_create(unsigned long long *ctx) {
    int ret = (int)ctx[4];
    if (ret != 0) {
        return ret;
    }
    int kern = (int)ctx[3];
    if (kern != 0) {
        return 0;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim_or_guest_init(cfg)) {
        return 0;
    }
    int family = (int)ctx[0];
    if (family == AF_VSOCK) {
        emit_event(EVT_DENY_SEAL, SEAL_REASON_VSOCK, 0, (__u64)family);
        return -EPERM;
    }
    if (cfg->init_net_inum != 0 && family != AF_UNIX) {
        __u32 net_inum = current_net_inum();
        if (net_inum == cfg->init_net_inum) {
            emit_event(EVT_DENY_SEAL, SEAL_REASON_INIT_NET, net_inum, (__u64)family);
            return -EPERM;
        }
    }
    return 0;
}

SEC("lsm/sb_remount")
int openshell_lsm_sb_remount(unsigned long long *ctx) {
    int ret = (int)ctx[2];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim_or_guest_init(cfg)) {
        return 0;
    }
    struct super_block *sb = (struct super_block *)ctx[0];
    if (!sb) {
        return 0;
    }
    dev_t s_dev = 0;
    CORE_READ(s_dev, sb, s_dev);
    if ((cfg->runtime_sb_dev != 0 && s_dev == cfg->runtime_sb_dev) ||
        (cfg->runtime_root_dev != 0 && s_dev == cfg->runtime_root_dev)) {
        emit_event(EVT_DENY_SEAL, SEAL_REASON_MOUNT, (__u32)s_dev, 0);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/sb_umount")
int openshell_lsm_sb_umount(unsigned long long *ctx) {
    int ret = (int)ctx[2];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim_or_guest_init(cfg)) {
        return 0;
    }
    struct vfsmount *mnt = (struct vfsmount *)ctx[0];
    if (!mnt) {
        return 0;
    }
    struct super_block *sb = 0;
    CORE_READ(sb, mnt, mnt_sb);
    if (!sb) {
        return 0;
    }
    dev_t s_dev = 0;
    CORE_READ(s_dev, sb, s_dev);
    if ((cfg->runtime_sb_dev != 0 && s_dev == cfg->runtime_sb_dev) ||
        (cfg->runtime_root_dev != 0 && s_dev == cfg->runtime_root_dev)) {
        emit_event(EVT_DENY_SEAL, SEAL_REASON_MOUNT, (__u32)s_dev, 0);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/locked_down")
int openshell_lsm_locked_down(unsigned long long *ctx) {
    int ret = (int)ctx[1];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim(cfg)) {
        return 0;
    }
    emit_event(EVT_DENY_SEAL, SEAL_REASON_LOCKDOWN, 0, (__u64)ctx[0]);
    return -EPERM;
}

// ---------------------------------------------------------------------------
// Plane 2: Workload filesystem_policy & mount bypass prevention
// ---------------------------------------------------------------------------

SEC("lsm/file_open")
int openshell_lsm_file_open(unsigned long long *ctx) {
    int ret = (int)ctx[1];
    if (ret != 0) {
        return ret;
    }
    struct file *file = (struct file *)ctx[0];
    if (!file) {
        return 0;
    }
    unsigned int flags = 0;
    CORE_READ(flags, file, f_flags);
    int is_write = ((flags & O_ACCMODE) == O_WRONLY) ||
                   ((flags & O_ACCMODE) == O_RDWR) ||
                   ((flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0);
    struct dentry *dentry = 0;
    CORE_READ(dentry, file, f_path.dentry);
    return check_dentry_access(dentry, is_write);
}

SEC("lsm/inode_create")
int openshell_lsm_inode_create(unsigned long long *ctx) {
    int ret = (int)ctx[3];
    if (ret != 0) {
        return ret;
    }
    struct dentry *dentry = (struct dentry *)ctx[1];
    return check_dentry_access(dentry, 1);
}

SEC("lsm/inode_unlink")
int openshell_lsm_inode_unlink(unsigned long long *ctx) {
    int ret = (int)ctx[2];
    if (ret != 0) {
        return ret;
    }
    struct dentry *dentry = (struct dentry *)ctx[1];
    return check_dentry_access(dentry, 1);
}

SEC("lsm/inode_rename")
int openshell_lsm_inode_rename(unsigned long long *ctx) {
    int ret = (int)ctx[4];
    if (ret != 0) {
        return ret;
    }
    struct dentry *old_dentry = (struct dentry *)ctx[1];
    int rc = check_dentry_access(old_dentry, 1);
    if (rc != 0) {
        return rc;
    }
    struct dentry *new_dentry = (struct dentry *)ctx[3];
    return check_dentry_access(new_dentry, 1);
}

SEC("lsm/inode_setattr")
int openshell_lsm_inode_setattr(unsigned long long *ctx) {
    int ret = (int)ctx[3];
    if (ret != 0) {
        return ret;
    }
    struct dentry *dentry = (struct dentry *)ctx[1];
    return check_dentry_access(dentry, 1);
}

SEC("lsm/sb_mount")
int openshell_lsm_sb_mount(unsigned long long *ctx) {
    int ret = (int)ctx[5];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim_or_guest_init(cfg)) {
        return 0;
    }
    const struct path *path = (const struct path *)ctx[1];
    if (!path) {
        return 0;
    }
    unsigned long flags = (unsigned long)ctx[3];
    struct dentry *target = 0;
    CORE_READ(target, path, dentry);
    if (!target) {
        return 0;
    }

    __u32 dev = 0;
    __u64 ino = 0;
    int seal_reason = is_protected_runtime_dentry(cfg, target, 1, &dev, &ino);
    if (seal_reason != 0) {
        emit_event(EVT_DENY_SEAL, SEAL_REASON_MOUNT, dev, ino);
        return -EPERM;
    }

    const struct policy_config *pcfg = get_policy_cfg();
    if (!pcfg || !pcfg->fs_enabled) {
        return 0;
    }
    __u32 mdev = dev;
    __u64 mino = ino;
    __u32 rule = lookup_fs_rule(target, &mdev, &mino);
    if (rule == FS_RULE_DENY) {
        emit_event(EVT_DENY_FS, rule, mdev, mino);
        return -EPERM;
    }
    // Block read-write remounts or writable shadow mounts over read-only policy paths.
    // Read-only remounts/binds (e.g. bwrap --ro-bind) stay allowed.
    if (rule == FS_RULE_RO && !(flags & MS_RDONLY)) {
        emit_event(EVT_DENY_FS, rule, mdev, mino);
        return -EPERM;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Plane 3: Workload process rules & kernel-sourced lineage/telemetry
// ---------------------------------------------------------------------------

SEC("lsm/bprm_check_security")
int openshell_lsm_bprm_check(unsigned long long *ctx) {
    int ret = (int)ctx[1];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active || current_is_shim(cfg)) {
        return 0;
    }
    struct linux_binprm *bprm = (struct linux_binprm *)ctx[0];
    if (!bprm) {
        return 0;
    }
    struct file *file = 0;
    CORE_READ(file, bprm, file);
    if (!file) {
        return 0;
    }
    struct dentry *dentry = 0;
    CORE_READ(dentry, file, f_path.dentry);
    struct inode *inode = 0;
    CORE_READ(inode, file, f_inode);
    __u32 dev = 0;
    __u64 ino = 0;
    if (inode) {
        struct super_block *sb = 0;
        CORE_READ(sb, inode, i_sb);
        if (sb) {
            dev_t s_dev = 0;
            CORE_READ(s_dev, sb, s_dev);
            dev = (__u32)s_dev;
        }
        unsigned long i_ino = 0;
        CORE_READ(i_ino, inode, i_ino);
        ino = (__u64)i_ino;
    }

    const struct policy_config *pcfg = get_policy_cfg();
    if (pcfg && pcfg->proc_enabled && inode) {
        struct inode_key key = { .dev = dev, ._pad = 0, .ino = ino };
        __u32 *rule = bpf_map_lookup_elem(&proc_rules, &key);
        if (rule) {
            if (*rule == PROC_RULE_DENY) {
                emit_event(EVT_DENY_PROC, PROC_RULE_DENY, dev, ino);
                return -EACCES;
            }
        } else if (pcfg->proc_default_deny) {
            emit_event(EVT_DENY_PROC, PROC_RULE_DENY, dev, ino);
            return -EACCES;
        }
    }

    emit_event(EVT_EXEC, 0, dev, ino);
    return 0;
}

SEC("lsm/task_alloc")
int openshell_lsm_task_alloc(unsigned long long *ctx) {
    int ret = (int)ctx[2];
    if (ret != 0) {
        return ret;
    }
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active) {
        return 0;
    }
    struct task_struct *child = (struct task_struct *)ctx[0];
    if (!child) {
        return 0;
    }
    unsigned long clone_flags = (unsigned long)ctx[1];
    __u32 parent_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct task_lineage *meta = bpf_task_storage_get(
        &task_meta,
        child,
        0,
        BPF_LOCAL_STORAGE_GET_F_CREATE
    );
    if (meta) {
        pid_t child_tgid = 0;
        CORE_READ(child_tgid, child, tgid);
        meta->tgid = (__u32)child_tgid;
        meta->parent_tgid = parent_tgid;
        // Only same-process threads of the shim inherit TASK_FLAG_SHIM;
        // forked workload children never inherit shim authority.
        if ((clone_flags & CLONE_THREAD) && is_shim_tgid(cfg, parent_tgid)) {
            meta->flags = TASK_FLAG_SHIM;
        } else {
            meta->flags = TASK_FLAG_WORKLOAD;
        }
        meta->_pad = 0;
    }
    return 0;
}

SEC("lsm/task_free")
int openshell_lsm_task_free(unsigned long long *ctx) {
    const struct seal_config *cfg = get_seal_cfg();
    if (!cfg || !cfg->active) {
        return 0;
    }
    struct task_struct *task = (struct task_struct *)ctx[0];
    if (!task || task_is_shim(cfg, task)) {
        return 0;
    }
    struct task_lineage *meta = bpf_task_storage_get(&task_meta, task, 0, 0);
    if (!meta || meta->flags != TASK_FLAG_WORKLOAD) {
        return 0;
    }
    pid_t pid = 0;
    pid_t tgid = 0;
    CORE_READ(pid, task, pid);
    CORE_READ(tgid, task, tgid);
    if (pid == tgid) {
        emit_event(EVT_TASK_EXIT, 0, 0, (__u64)tgid);
    }
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
