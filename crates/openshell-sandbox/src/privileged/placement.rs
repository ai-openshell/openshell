// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Placement of privileged (true guest root) workload processes.
//!
//! A long-lived `workload-hold` helper child holds the workload's dedicated
//! mount namespace (pivoted into the separate workload rootfs with
//! `MS_REC | MS_PRIVATE`), child PID namespace (where it is workload PID 1),
//! child cgroup namespace (under the runtime-owned freezer cgroup), and
//! loopback-only network namespace (`CLONE_NEWNET`, `lo` up).
//!
//! Every workload process (main, exec, PTY, SFTP) is spawned on the
//! `WorkloadLauncher` thread:
//! 1. The launcher switches `pid_ns_for_children` to `workload_pid_ns`, forks
//!    the child into the workload PID namespace, and restores its own PID ns.
//! 2. Between `fork` and `exec` (`pre_exec`, async-signal-safe), the child
//!    writes itself into the workload cgroup, enters the holder's cgroup, net,
//!    and mount namespaces, stays guest `UID 0`, drops only kernel-escape
//!    capabilities (`CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_SYS_BOOT`,
//!    `CAP_BPF`, `CAP_PERFMON`), opens its session/PTY, `chdir`s to `workdir`,
//!    and installs the minimal privileged seccomp filter (`io_uring` + nested
//!    `NEW_LISTENER` blocked, no `PR_SET_NO_NEW_PRIVS`).

#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use super::{
    RUNTIME_TLS_DIR, WORKLOAD_CGROUP_DIR, WORKLOAD_CGROUP_INIT_DIR, WORKLOAD_HOLD_ROLE,
    WORKLOAD_TLS_DIR,
};
use crate::linux::child_seccomp::{self, ChildHardeningProgram};

/// Kernel capabilities dropped from the workload bounding and active sets.
/// Everything else (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`,
/// `CAP_SETUID`, `CAP_SETGID`, `CAP_MKNOD`, `CAP_DAC_OVERRIDE`, ...) stays
/// available to guest root.
const DROPPED_CAPS: [u32; 5] = [
    16, // CAP_SYS_MODULE
    17, // CAP_SYS_RAWIO
    22, // CAP_SYS_BOOT
    38, // CAP_PERFMON
    39, // CAP_BPF
];

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drop `DROPPED_CAPS` from bounding, effective, permitted, and inheritable sets.
/// Async-signal-safe: only `prctl` and `capget`/`capset` syscalls.
fn drop_kernel_escape_capabilities() -> io::Result<()> {
    for cap in DROPPED_CAPS {
        // SAFETY: PR_CAPBSET_DROP takes scalar capability numbers.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(err);
            }
        }
    }
    let mut header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData::default(); 2];
    // SAFETY: `header` and `data` match Linux v3 capget/capset ABI.
    if unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for cap in DROPPED_CAPS {
        let word = (cap / 32) as usize;
        let bit = 1u32 << (cap % 32);
        data[word].effective &= !bit;
        data[word].permitted &= !bit;
        data[word].inheritable &= !bit;
    }
    // SAFETY: `header` and `data` are valid v3 capability buffers.
    if unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bring up `lo` in the calling process's current network namespace.
pub fn loopback_up() -> io::Result<()> {
    // SAFETY: AF_INET datagram socket used only for `lo` SIOCGIFFLAGS/SIOCSIFFLAGS.
    unsafe {
        let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut request: libc::ifreq = std::mem::zeroed();
        for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo\0") {
            *slot = libc::c_char::from_ne_bytes([*byte]);
        }
        #[allow(clippy::cast_possible_truncation, trivial_numeric_casts)]
        let mut rc = libc::ioctl(socket, libc::SIOCGIFFLAGS as libc::Ioctl, &raw mut request);
        if rc == 0 {
            #[allow(clippy::cast_possible_truncation)]
            {
                request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            }
            #[allow(clippy::cast_possible_truncation, trivial_numeric_casts)]
            {
                rc = libc::ioctl(
                    socket,
                    libc::SIOCSIFFLAGS as libc::Ioctl,
                    &raw const request,
                );
            }
        }
        let err = io::Error::last_os_error();
        libc::close(socket);
        if rc != 0 {
            return Err(err);
        }
    }
    Ok(())
}

fn cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two fresh descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptors are newly created and owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn mount_call(
    source: Option<&CString>,
    target: &CString,
    fstype: Option<&CString>,
    flags: libc::c_ulong,
    data: Option<&CString>,
) -> io::Result<()> {
    let src = source.map_or(std::ptr::null(), |s| s.as_ptr());
    let fs = fstype.map_or(std::ptr::null(), |s| s.as_ptr());
    let d = data.map_or(std::ptr::null(), |s| s.as_ptr().cast());
    // SAFETY: all non-null pointers are NUL-terminated CStrings alive for the call.
    if unsafe { libc::mount(src, target.as_ptr(), fs, flags, d) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn components(path: &str) -> io::Result<Vec<CString>> {
    path.trim_start_matches('/')
        .split('/')
        .map(|part| {
            if part.is_empty() || part == "." || part == ".." {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsafe workload mount target {path}"),
                ));
            }
            cstring(part)
        })
        .collect()
}

fn open_beneath_no_follow(root: RawFd, parts: &[CString], create: bool) -> io::Result<OwnedFd> {
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut current: Option<OwnedFd> = None;
    for part in parts {
        let parent = current.as_ref().map_or(root, AsRawFd::as_raw_fd);
        // SAFETY: `parent` is an open directory fd and `part` is NUL-terminated.
        let mut fd = unsafe { libc::openat(parent, part.as_ptr(), flags) };
        if fd < 0 && create && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            // SAFETY: same.
            unsafe { libc::mkdirat(parent, part.as_ptr(), 0o755) };
            // SAFETY: same.
            fd = unsafe { libc::openat(parent, part.as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zeroed stat buffer for fstat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `owned` is a live file descriptor and `st` is writable.
        if unsafe { libc::fstat(owned.as_raw_fd(), &raw mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        current = Some(owned);
    }
    current.ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
}

fn bind_onto_pinned(
    workload_root_fd: RawFd,
    source: &str,
    target_rel: &str,
    read_only: bool,
    recursive: bool,
) -> io::Result<()> {
    let mut parts = components(target_rel)?;
    let leaf = parts
        .pop()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    let parent_fd = if parts.is_empty() {
        None
    } else {
        Some(open_beneath_no_follow(workload_root_fd, &parts, true)?)
    };
    let parent_raw = parent_fd
        .as_ref()
        .map_or(workload_root_fd, AsRawFd::as_raw_fd);
    let src_meta = std::fs::symlink_metadata(source)?;
    if src_meta.is_dir() {
        // Ensure leaf directory exists without following symlinks.
        let _leaf_fd = open_beneath_no_follow(parent_raw, std::slice::from_ref(&leaf), true)?;
    } else {
        // Ensure leaf file mountpoint exists without following symlinks.
        // SAFETY: `parent_raw` is an open directory fd and `leaf` is NUL-terminated.
        let fd = unsafe {
            libc::openat(
                parent_raw,
                leaf.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(err);
            }
        } else {
            // SAFETY: fresh descriptor.
            unsafe { libc::close(fd) };
        }
    }
    let src = cstring(source)?;
    // SAFETY: `fchdir` pins the parent directory by descriptor; mounting and
    // remounting `leaf` by single path component operates on the newly stacked
    // bind mount rather than the covered mountpoint dentry.
    if unsafe { libc::fchdir(parent_raw) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let bind_flags = if recursive {
        libc::MS_BIND | libc::MS_REC
    } else {
        libc::MS_BIND
    };
    mount_call(Some(&src), &leaf, None, bind_flags, None)
        .map_err(|e| io::Error::new(e.kind(), format!("bind {source} -> {target_rel}: {e}")))?;
    if read_only {
        mount_call(
            None,
            &leaf,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("remount-ro {target_rel}: {e}")))?;
    }
    Ok(())
}

fn unescape_mountinfo_path(raw: &str) -> String {
    raw.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn is_excluded_container_submount(path: &str) -> bool {
    path == "/"
        || path == "/proc"
        || path.starts_with("/proc/")
        || path == "/dev"
        || path.starts_with("/dev/")
        || path == "/sys"
        || path.starts_with("/sys/")
        || path == "/run/openshell"
        || path.starts_with("/run/openshell/")
        || path == "/.openshell"
        || path.starts_with("/.openshell/")
        || path == "/etc/openshell-tls"
        || path.starts_with("/etc/openshell-tls/")
}

/// Collect container submounts (such as `/etc/hosts`, `/etc/resolv.conf`,
/// `/etc/hostname`, `/sandbox`, and user volume mounts) from
/// `/proc/self/mountinfo` in mount order, excluding runtime-owned and
/// virtual-FS paths.
fn collect_container_submounts() -> io::Result<Vec<(String, bool)>> {
    let text = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mut seen = std::collections::HashSet::new();
    let mut mounts = Vec::new();
    for line in text.lines() {
        let mut fields = line.split(' ');
        let Some(mp_raw) = fields.nth(4) else {
            continue;
        };
        let Some(opts) = fields.next() else {
            continue;
        };
        let mp = unescape_mountinfo_path(mp_raw);
        if is_excluded_container_submount(&mp) || !seen.insert(mp.clone()) {
            continue;
        }
        let read_only = opts.split(',').any(|opt| opt == "ro");
        mounts.push((mp, read_only));
    }
    Ok(mounts)
}

/// Entrypoint of the hidden `workload-hold` role.
///
/// Runs as workload PID 1 inside its own PID, mount, cgroup, and loopback-only
/// network namespaces. Pivots into `--root`, mounts fresh `/proc`, `/dev/shm`,
/// and read-only `/etc/openshell-tls`, signals readiness on stdout (`"OK\n"`),
/// and reaps workload orphans until signaled to exit.
pub fn run_workload_hold(workload_root: &Path) -> io::Result<()> {
    // Bring up loopback in the fresh CLONE_NEWNET namespace.
    loopback_up()?;

    // Private mount propagation so nothing propagates back to PID 1's tree.
    let slash = cstring("/")?;
    mount_call(None, &slash, None, libc::MS_REC | libc::MS_PRIVATE, None)?;

    // Determine the target mount point for `pivot_root`.
    // - Dedicated workload disk (VM driver): `workload_root` is e.g. `/newroot`,
    //   separate from the read-only runtime root `/`.
    // - Container root (Kata Pod): `workload_root` is `/`; bind `/` (non-recursively,
    //   so runtime submounts under `/run/openshell` and `/.openshell` are excluded)
    //   onto `/run/openshell/workload` and pivot into it.
    let container_root_mode = workload_root == Path::new("/");
    let container_submounts = if container_root_mode {
        collect_container_submounts()?
    } else {
        Vec::new()
    };
    let pivot_target: PathBuf = if container_root_mode {
        let target = PathBuf::from("/run/openshell/workload");
        std::fs::create_dir_all(&target)?;
        let target_c = cstring("/run/openshell/workload")?;
        mount_call(Some(&slash), &target_c, None, libc::MS_BIND, None)
            .map_err(|e| io::Error::new(e.kind(), format!("bind / -> workload root: {e}")))?;
        target
    } else {
        let root_c = cstring(workload_root.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 workload root")
        })?)?;
        mount_call(
            Some(&root_c),
            &root_c,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )?;
        workload_root.to_path_buf()
    };

    let root_dir = File::open(&pivot_target)?;
    let root_fd = root_dir.as_raw_fd();

    // Bind /dev and /sys from host guest into the workload root, plus read-only
    // CA bundle from runtime-owned /run/openshell/tls.
    for path in ["/dev", "/sys"] {
        bind_onto_pinned(root_fd, path, path, false, true)?;
    }
    if container_root_mode {
        // Preserve non-runtime container submounts (kubelet /etc/hosts,
        // /etc/resolv.conf, /etc/hostname, /sandbox PVC, user volume mounts)
        // non-recursively in mount order so runtime mounts under /run/openshell
        // and /.openshell never leak into the workload mount namespace.
        for (mp, read_only) in &container_submounts {
            bind_onto_pinned(root_fd, mp, mp, *read_only, false)?;
        }
        // Mask /.openshell with an empty read-only tmpfs so runtime binaries
        // and bootstrap staging paths are inaccessible to workload processes.
        if pivot_target.join(".openshell").is_dir() {
            let parts = components("/.openshell")?;
            let target_fd = open_beneath_no_follow(root_fd, &parts, false)?;
            let tmpfs = cstring("tmpfs")?;
            let dot = cstring(".")?;
            let opts = cstring("size=4k,mode=0555")?;
            // SAFETY: `fchdir` pins `/.openshell` inside the workload root.
            if unsafe { libc::fchdir(target_fd.as_raw_fd()) } == 0 {
                let _ = mount_call(
                    Some(&tmpfs),
                    &dot,
                    Some(&tmpfs),
                    libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    Some(&opts),
                );
            }
        }
    }
    if Path::new(RUNTIME_TLS_DIR).is_dir() {
        bind_onto_pinned(root_fd, RUNTIME_TLS_DIR, WORKLOAD_TLS_DIR, true, true)?;
    }

    // Pivot into workload_root and unmount the old runtime root completely so
    // no runtime paths exist in the workload's mount namespace.
    // SAFETY: `root_fd` is an open directory descriptor to the workload root.
    if unsafe { libc::fchdir(root_fd) } != 0 {
        return Err(io::Error::last_os_error());
    }
    drop(root_dir);
    let dot = cstring(".")?;
    // SAFETY: `dot` is a valid NUL-terminated path for `pivot_root(".", ".")`.
    if unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), dot.as_ptr()) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("pivot_root: {e}")));
    }
    // SAFETY: `dot` is a valid NUL-terminated path detaching the old root mount.
    if unsafe { libc::umount2(dot.as_ptr(), libc::MNT_DETACH) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("umount old root: {e}")));
    }
    // SAFETY: `slash` is a valid NUL-terminated path `"/"`.
    if unsafe { libc::chdir(slash.as_ptr()) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("chdir /: {e}")));
    }

    // Mount a fresh /proc for this child PID namespace so guest PID 1
    // (openshell-sandbox) is completely invisible to workload processes.
    let proc_t = cstring("/proc")?;
    let proc_fs = cstring("proc")?;
    let _ = std::fs::create_dir_all("/proc");
    mount_call(
        Some(&proc_fs),
        &proc_t,
        Some(&proc_fs),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("mount /proc: {e}")))?;

    // Ensure /dev/pts, /dev/shm (needed by Chrome!), and /tmp are mounted.
    let _ = std::fs::create_dir_all("/dev/pts");
    let _ = std::fs::create_dir_all("/dev/shm");
    let _ = std::fs::create_dir_all("/tmp");
    let devpts = cstring("devpts")?;
    let devpts_t = cstring("/dev/pts")?;
    let devpts_opts = cstring("newinstance,ptmxmode=0666,mode=0620")?;
    let _ = mount_call(
        Some(&devpts),
        &devpts_t,
        Some(&devpts),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some(&devpts_opts),
    );
    let tmpfs = cstring("tmpfs")?;
    let shm_t = cstring("/dev/shm")?;
    let shm_opts = cstring("mode=1777,size=512m")?;
    let _ = mount_call(
        Some(&tmpfs),
        &shm_t,
        Some(&tmpfs),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(&shm_opts),
    );
    let cgroup2 = cstring("cgroup2")?;
    let cgroup_t = cstring("/sys/fs/cgroup")?;
    let _ = std::fs::create_dir_all("/sys/fs/cgroup");
    let _ = mount_call(
        Some(&cgroup2),
        &cgroup_t,
        Some(&cgroup2),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    );

    // Signal readiness to openshell-sandbox on stdout, then stay alive as
    // workload PID 1 reaping any orphaned descendants.
    {
        let mut out = io::stdout().lock();
        out.write_all(b"OK\n")?;
        out.flush()?;
    }

    loop {
        let mut status = 0;
        // SAFETY: waitpid(-1, ...) reaps any orphaned child in this PID namespace.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };
        if pid < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
}

/// Session setup for a placed child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildSession {
    Pipes,
    Terminal,
}

/// Manages the pinned workload namespaces and places every workload child.
pub struct PrivilegedPlacement {
    workload_root: PathBuf,
    holder: Mutex<Child>,
    holder_pid: u32,
    init_pid_ns: OwnedFd,
    workload_pid_ns: OwnedFd,
    workload_mnt_ns: OwnedFd,
    workload_net_ns: OwnedFd,
    workload_cgroup_ns: Option<OwnedFd>,
    workload_cgroup_procs: Option<CString>,
    workload_net_inum: u32,
}

impl PrivilegedPlacement {
    /// Start the `workload-hold` namespace holder and pin all workload namespace fds.
    pub fn start(workload_root: PathBuf, has_cgroup_v2: bool) -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let init_pid_ns = File::open("/proc/self/ns/pid")?.into();

        // Prepare cgroup v2 subtree if available:
        // /sys/fs/cgroup/openshell-workload       (freezer owned by shim)
        // /sys/fs/cgroup/openshell-workload/init  (workload's cgroupns root)
        let cgroup_procs = if has_cgroup_v2 {
            let _ = std::fs::create_dir_all(WORKLOAD_CGROUP_INIT_DIR);
            // Enable controllers on the parent if possible (best effort).
            let _ = std::fs::write(
                Path::new(WORKLOAD_CGROUP_DIR).join("cgroup.subtree_control"),
                "+cpu +memory +pids",
            );
            Some(cstring(&format!(
                "{WORKLOAD_CGROUP_INIT_DIR}/cgroup.procs"
            ))?)
        } else {
            None
        };

        // Fork the holder into its own PID, mount, network, and cgroup namespaces.
        // We unshare(CLONE_NEWPID) on a short-lived helper thread so the main
        // runtime thread's `pid_ns_for_children` is never disturbed.
        let root_arg = workload_root.clone();
        let cg_procs_clone = cgroup_procs.clone();
        let holder = std::thread::Builder::new()
            .name("openshell-holder-spawn".to_string())
            .spawn(move || -> io::Result<Child> {
                // SAFETY: unshare(CLONE_NEWPID) on this dedicated short-lived thread
                // makes its immediate child PID 1 of the new PID namespace.
                if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut cmd = Command::new(&exe);
                cmd.args([
                    WORKLOAD_HOLD_ROLE,
                    "--root",
                    root_arg.to_str().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 workload root")
                    })?,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());

                let cg_procs_pre = cg_procs_clone;
                // SAFETY: pre_exec runs only async-signal-safe syscalls.
                unsafe {
                    cmd.pre_exec(move || {
                        if let Some(ref procs_path) = cg_procs_pre {
                            let fd =
                                libc::open(procs_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                            if fd >= 0 {
                                let _ = libc::write(fd, b"0\n".as_ptr().cast(), 2);
                                libc::close(fd);
                            }
                        }
                        let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWNET;
                        if cg_procs_pre.is_some() {
                            flags |= libc::CLONE_NEWCGROUP;
                        }
                        if libc::unshare(flags) != 0 {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                cmd.spawn()
            })
            .map_err(|e| io::Error::other(format!("spawn holder thread: {e}")))?
            .join()
            .map_err(|_| io::Error::other("holder spawn thread panicked"))??;

        let mut holder = holder;
        let holder_pid = holder.id();

        // Wait for "OK\n" from workload-hold so mount/net/proc setup is complete.
        let mut stdout = holder
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("workload-hold stdout missing"))?;
        let mut buf = [0u8; 3];
        stdout.read_exact(&mut buf).map_err(|e| {
            let _ = holder.kill();
            let _ = holder.wait();
            io::Error::other(format!("workload-hold failed before ready: {e}"))
        })?;
        if &buf != b"OK\n" {
            let _ = holder.kill();
            let _ = holder.wait();
            return Err(io::Error::other(
                "workload-hold sent unexpected readiness token",
            ));
        }

        let workload_pid_ns: OwnedFd = File::open(format!("/proc/{holder_pid}/ns/pid"))?.into();
        let workload_mnt_ns: OwnedFd = File::open(format!("/proc/{holder_pid}/ns/mnt"))?.into();
        let net_file = File::open(format!("/proc/{holder_pid}/ns/net"))?;
        #[allow(clippy::cast_possible_truncation)]
        let workload_net_inum = net_file.metadata()?.ino() as u32;
        let workload_net_ns: OwnedFd = net_file.into();
        let workload_cgroup_ns = has_cgroup_v2
            .then(|| File::open(format!("/proc/{holder_pid}/ns/cgroup")).map(Into::into))
            .transpose()?;

        Ok(Self {
            workload_root,
            holder: Mutex::new(holder),
            holder_pid,
            init_pid_ns,
            workload_pid_ns,
            workload_mnt_ns,
            workload_net_ns,
            workload_cgroup_ns,
            workload_cgroup_procs: cgroup_procs,
            workload_net_inum,
        })
    }

    #[must_use]
    pub fn workload_root(&self) -> &Path {
        &self.workload_root
    }

    #[must_use]
    pub const fn holder_pid(&self) -> u32 {
        self.holder_pid
    }

    #[must_use]
    pub const fn workload_net_inum(&self) -> u32 {
        self.workload_net_inum
    }

    /// Execute `spawn_fn` with `pid_ns_for_children` temporarily switched to the
    /// workload's PID namespace (must be called on the single-threaded
    /// `WorkloadLauncher` thread).
    pub fn with_workload_pid_ns<T>(
        &self,
        spawn_fn: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        // SAFETY: switching `pid_ns_for_children` on the serialized launcher
        // thread puts the immediate forked child inside the workload PID ns.
        if unsafe { libc::setns(self.workload_pid_ns.as_raw_fd(), libc::CLONE_NEWPID) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let result = spawn_fn();
        // Always restore the launcher thread's `pid_ns_for_children`.
        // SAFETY: `init_pid_ns` is the launcher's original PID namespace fd.
        let _ = unsafe { libc::setns(self.init_pid_ns.as_raw_fd(), libc::CLONE_NEWPID) };
        result
    }

    /// Install the async-signal-safe `pre_exec` placement hook onto `cmd`.
    ///
    /// Returns a `PlacementGate` whose `finish()` must be called after spawning.
    pub fn install(
        &self,
        cmd: &mut Command,
        workdir: &str,
        session: ChildSession,
    ) -> io::Result<()> {
        let mut hardening: ChildHardeningProgram = child_seccomp::prepare_privileged()?;
        let mnt_fd = self.workload_mnt_ns.as_raw_fd();
        let net_fd = self.workload_net_ns.as_raw_fd();
        let cgroup_fd = self.workload_cgroup_ns.as_ref().map(AsRawFd::as_raw_fd);
        let cgroup_procs = self.workload_cgroup_procs.clone();
        let workdir_c = cstring(if workdir.is_empty() { "/" } else { workdir })?;
        let slash_c = cstring("/")?;

        // SAFETY: Every operation inside `pre_exec` uses pre-allocated memory
        // and async-signal-safe Linux syscalls.
        unsafe {
            cmd.pre_exec(move || {
                // 1. Place child into the runtime-owned workload cgroup before
                // entering the child's cgroup namespace.
                if let Some(ref procs_path) = cgroup_procs {
                    let fd = libc::open(procs_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                    if fd >= 0 {
                        let _ = libc::write(fd, b"0\n".as_ptr().cast(), 2);
                        libc::close(fd);
                    }
                }
                if let Some(cg_fd) = cgroup_fd
                    && libc::setns(cg_fd, libc::CLONE_NEWCGROUP) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                // 2. Enter the loopback-only workload network namespace and the
                // pivoted workload mount namespace.
                if libc::setns(net_fd, libc::CLONE_NEWNET) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setns(mnt_fd, libc::CLONE_NEWNS) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // 3. Session / controlling terminal setup.
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if session == ChildSession::Terminal {
                    #[allow(clippy::cast_possible_truncation, trivial_numeric_casts)]
                    if libc::ioctl(0, libc::TIOCSCTTY as libc::Ioctl, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                // 4. Switch to workdir (falling back to "/" if absent).
                if libc::chdir(workdir_c.as_ptr()) != 0 {
                    let _ = libc::chdir(slash_c.as_ptr());
                }
                // 5. Install the privileged seccomp filter (blocks io_uring and
                // nested NEW_LISTENER) BEFORE dropping caps (no PR_SET_NO_NEW_PRIVS).
                hardening.install_privileged()?;
                // 6. Keep guest UID/GID 0, dropping only kernel-escape capabilities.
                drop_kernel_escape_capabilities()?;
                Ok(())
            });
        }
        Ok(())
    }

    /// Terminate the workload namespace holder when shutting down.
    pub fn terminate_holder(&self) {
        if let Ok(mut holder) = self.holder.lock() {
            let _ = holder.kill();
            let _ = holder.wait();
        }
    }
}

impl Drop for PrivilegedPlacement {
    fn drop(&mut self) {
        self.terminate_holder();
    }
}

/// Also keep `pipe_cloexec` used for future readiness pipes if needed.
#[allow(dead_code)]
fn _unused_pipe_ref() {
    let _ = pipe_cloexec;
}
