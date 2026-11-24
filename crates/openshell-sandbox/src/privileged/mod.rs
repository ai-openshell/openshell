// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Privileged (true guest root) VM runtime with boot-once BPF LSM sealing.

#![allow(unsafe_code)]

pub mod bpf_lsm;
pub mod path_view;
pub mod placement;

use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openshell_core::policy::SandboxPolicy;
use openshell_sandbox_backend::privileged::{
    PrivilegedGuestProfile, PrivilegedSandboxAuditEvidence,
};

use crate::linux::workload_launcher::WorkloadLauncher;
use crate::network_broker::NetworkBroker;
use bpf_lsm::{BpfLsmHandle, SealConfig, kernel_dev};
use placement::PrivilegedPlacement;

/// Runtime-private root tmpfs directory (holds bootstrap, CA material, state).
pub const RUNTIME_BASE_DIR: &str = "/run/openshell";
/// Runtime-owned CA material, bind-mounted read-only into the workload.
pub const RUNTIME_TLS_DIR: &str = "/run/openshell/tls";
/// Where the workload sees the CA material.
pub const WORKLOAD_TLS_DIR: &str = "/etc/openshell-tls";
/// Runtime-owned freezer cgroup parent (outside the workload's cgroupns).
pub const WORKLOAD_CGROUP_DIR: &str = "/sys/fs/cgroup/openshell-workload";
/// Workload's child cgroup directory (the workload's cgroupns root).
pub const WORKLOAD_CGROUP_INIT_DIR: &str = "/sys/fs/cgroup/openshell-workload/init";

/// Hidden subcommand for the workload namespace holder (workload PID 1).
pub const WORKLOAD_HOLD_ROLE: &str = "workload-hold";
/// Hidden subcommand for the cgroup freezer qualification canary.
pub const FREEZE_CANARY_ROLE: &str = "guest-freeze-canary";
/// Hidden subcommand for placed SFTP helper (runs inside workload namespaces).
pub const SFTP_ROLE: &str = "sftp-server";

/// Freezer-qualification canary: arms a periodic `SIGCONT` timer and writes
/// progress bytes until killed. Proves `cgroup.freeze` holds even against a
/// hostile self-resuming workload.
pub fn run_freeze_canary() -> io::Result<()> {
    // SAFETY: zeroed sigevent/itimerspec for timer_create/timer_settime.
    unsafe {
        let mut event: libc::sigevent = std::mem::zeroed();
        event.sigev_notify = libc::SIGEV_SIGNAL;
        event.sigev_signo = libc::SIGCONT;
        let mut timer: libc::timer_t = std::mem::zeroed();
        if libc::timer_create(libc::CLOCK_MONOTONIC, &raw mut event, &raw mut timer) != 0 {
            return Err(io::Error::last_os_error());
        }
        let period = libc::timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        let spec = libc::itimerspec {
            it_interval: period,
            it_value: period,
        };
        if libc::timer_settime(timer, 0, &raw const spec, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut stdout = io::stdout().lock();
    loop {
        stdout.write_all(b".")?;
        stdout.flush()?;
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Serve SFTP over stdin/stdout inside the placed workload namespaces.
pub fn run_sftp_helper(root: PathBuf) -> miette::Result<()> {
    use miette::IntoDiagnostic as _;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;
    runtime.block_on(crate::sftp::serve(
        tokio::io::join(tokio::io::stdin(), tokio::io::stdout()),
        root,
    ))
}

/// Find a login shell confined to `workload_root`.
#[must_use]
pub fn find_workload_login_shell(workload_root: &Path) -> Option<String> {
    for candidate in ["/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh"] {
        if path_view::is_executable_in_root(workload_root, Path::new(candidate)) {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Detect a login shell inside `workload_root`, defaulting to `/bin/sh`.
#[must_use]
pub fn detect_workload_login_shell(workload_root: &Path) -> String {
    find_workload_login_shell(workload_root).unwrap_or_else(|| "/bin/sh".to_string())
}

/// Read an image-embedded sandbox policy confined to `workload_root`.
pub fn discover_workload_image_policy(workload_root: &Path) -> Option<String> {
    for path in [
        "/etc/openshell/policy.yaml",
        "/etc/openshell/policy.yml",
        "/.openshell/policy.yaml",
    ] {
        if let Ok(content) =
            path_view::read_to_string_in_root(workload_root, Path::new(path), 1024 * 1024)
            && !content.trim().is_empty()
        {
            return Some(content);
        }
    }
    None
}

fn qualify_cgroup_freezer() -> bool {
    let freeze_file = Path::new(WORKLOAD_CGROUP_DIR).join("cgroup.freeze");
    let procs_file = Path::new(WORKLOAD_CGROUP_INIT_DIR).join("cgroup.procs");
    let _ = fs::create_dir_all(WORKLOAD_CGROUP_INIT_DIR);
    if !freeze_file.exists() || !procs_file.exists() {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Ok(mut child) = Command::new(exe)
        .arg(FREEZE_CANARY_ROLE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let pid = child.id();
    if fs::write(&procs_file, format!("{pid}\n")).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    };
    let mut byte = [0u8; 1];
    if stdout.read_exact(&mut byte).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    // Freeze the cgroup and confirm frozen=1 in cgroup.events.
    if fs::write(&freeze_file, "1\n").is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut frozen = false;
    while Instant::now() < deadline {
        if let Ok(events) = fs::read_to_string(Path::new(WORKLOAD_CGROUP_DIR).join("cgroup.events"))
            && events.lines().any(|line| line.trim() == "frozen 1")
        {
            frozen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = fs::write(&freeze_file, "0\n");
    let _ = child.wait();
    frozen
}

/// Active privileged (true guest root) runtime owned by `BoundaryServer`.
pub struct PrivilegedRuntime {
    profile: PrivilegedGuestProfile,
    workload_root: PathBuf,
    placement: Arc<PrivilegedPlacement>,
    bpf_lsm: Mutex<BpfLsmHandle>,
    standing_freeze: bool,
    init_net_isolated: bool,
    seccomp_addfd_send: bool,
    kernel_release: String,
    native_architecture: String,
}

impl PrivilegedRuntime {
    /// Bootstrap the privileged runtime, qualify cgroup freeze, start the
    /// workload namespace holder, arm and freeze the boot-once BPF LSM, and
    /// return the runtime plus the networking `WorkloadLauncher` and `NetworkBroker`.
    pub fn start(
        profile: PrivilegedGuestProfile,
        workload_root: PathBuf,
        protected_control_port: Option<u16>,
    ) -> anyhow::Result<(Arc<Self>, WorkloadLauncher, NetworkBroker)> {
        profile
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid privileged profile: {e}"))?;

        let uid = nix::unistd::geteuid().as_raw();
        if uid != 0 {
            anyhow::bail!("--privileged requires guest root (UID 0), got UID {uid}");
        }

        // Harden the shim process itself before forking anything.
        // SAFETY: PR_SET_DUMPABLE=0 and RLIMIT_CORE=0 are scalar process transitions.
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let _ = libc::setrlimit(libc::RLIMIT_CORE, &raw const zero);
        }

        // Ensure /run/openshell is a dedicated runtime-private tmpfs mount
        // (distinct from `/`) so BPF LSM guards it even when the container's
        // `/` is itself the workload rootfs (e.g. Kata Containers on k8s).
        fs::create_dir_all(RUNTIME_BASE_DIR)?;
        let root_dev_raw = fs::metadata("/")?.dev();
        if fs::metadata(RUNTIME_BASE_DIR)?.dev() == root_dev_raw {
            let src = std::ffi::CString::new("tmpfs").expect("static");
            let dst = std::ffi::CString::new(RUNTIME_BASE_DIR).expect("static");
            let opts = std::ffi::CString::new("mode=0700").expect("static");
            // SAFETY: all pointers are NUL-terminated static strings.
            if unsafe {
                libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    src.as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    opts.as_ptr().cast(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        fs::create_dir_all(RUNTIME_TLS_DIR)?;
        fs::set_permissions(RUNTIME_TLS_DIR, fs::Permissions::from_mode(0o755))?;

        let container_root_mode = workload_root == Path::new("/");
        let runtime_root_dev = if container_root_mode {
            0
        } else {
            kernel_dev(root_dev_raw)
        };
        let runtime_sb_dev = kernel_dev(fs::metadata(RUNTIME_BASE_DIR)?.dev());
        let workload_root_dev = kernel_dev(fs::metadata(&workload_root)?.dev());
        if !container_root_mode && workload_root_dev == runtime_root_dev {
            anyhow::bail!(
                "workload root {} must reside on a separate mount from runtime root /",
                workload_root.display()
            );
        }
        if runtime_sb_dev == workload_root_dev {
            anyhow::bail!(
                "runtime state dir {RUNTIME_BASE_DIR} must reside on a separate mount from workload root {}",
                workload_root.display()
            );
        }

        // Qualify cgroup.freeze before launching workload-hold.
        let has_cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        let standing_freeze = if has_cgroup_v2 {
            qualify_cgroup_freezer()
        } else {
            false
        };
        let (cgroup_sb_dev, freezer_cgroup_ino) =
            if has_cgroup_v2 && let Ok(meta) = fs::metadata(WORKLOAD_CGROUP_DIR) {
                (kernel_dev(meta.dev()), meta.ino())
            } else {
                (0, 0)
            };

        // Measure init_net inode before launching workload-hold in CLONE_NEWNET.
        #[allow(clippy::cast_possible_truncation)]
        let init_net_inum = fs::metadata("/proc/self/ns/net")?.ino() as u32;

        // Spawn workload-hold in its dedicated mount, PID, cgroup, and net namespaces.
        let placement = Arc::new(
            PrivilegedPlacement::start(workload_root.clone(), has_cgroup_v2)
                .map_err(|e| anyhow::anyhow!("start privileged workload namespaces: {e}"))?,
        );
        let init_net_isolated = placement.workload_net_inum() != init_net_inum;
        if !init_net_isolated {
            anyhow::bail!("workload network namespace did not isolate from init_net");
        }

        // Arm and freeze the boot-once BPF LSM seal BEFORE starting any workload code.
        let shim_tgid = std::process::id();
        let mut bpf_lsm = BpfLsmHandle::load_and_seal(SealConfig {
            active: 1,
            shim_tgid,
            launcher_tgid: 0,
            runtime_sb_dev,
            runtime_root_dev,
            init_net_inum,
            freezer_cgroup_ino,
            cgroup_sb_dev,
            guest_parent_tgid: 0,
        })?;
        bpf_lsm.spawn_telemetry_reader()?;

        // Qualify seccomp_notify ADDFD support.
        let seccomp_probe = crate::linux::seccomp_notify::probe_notification_api()
            .map_err(|e| anyhow::anyhow!("seccomp_notify qualification failed: {e}"))?;
        let seccomp_addfd_send = seccomp_probe.addfd_send();

        // Start the networking-only seccomp_notify WorkloadLauncher (without
        // PR_SET_NO_NEW_PRIVS) and attach our privileged placement.
        let (launcher, listener) =
            crate::linux::workload_launcher::start_privileged_networking()
                .map_err(|e| anyhow::anyhow!("start privileged workload launcher: {e}"))?;
        let launcher = launcher.with_privileged_placement(Arc::clone(&placement));

        let broker = NetworkBroker::start(listener, protected_control_port)
            .map_err(|e| anyhow::anyhow!("start privileged network broker: {e}"))?;

        let (kernel_release, native_architecture) = read_utsname();

        let runtime = Arc::new(Self {
            profile,
            workload_root,
            placement,
            bpf_lsm: Mutex::new(bpf_lsm),
            standing_freeze,
            init_net_isolated,
            seccomp_addfd_send,
            kernel_release,
            native_architecture,
        });

        Ok((runtime, launcher, broker))
    }

    #[must_use]
    pub fn workload_root(&self) -> &Path {
        &self.workload_root
    }

    #[must_use]
    pub fn placement(&self) -> &Arc<PrivilegedPlacement> {
        &self.placement
    }

    #[must_use]
    pub const fn standing_freeze(&self) -> bool {
        self.standing_freeze
    }

    /// Apply or live-reload `filesystem_policy` and `process` rules in the BPF LSM maps.
    pub fn apply_policy(&self, policy: &SandboxPolicy, workdir: &str) -> anyhow::Result<usize> {
        let mut lsm = self
            .bpf_lsm
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lsm.apply_policy(&self.workload_root, policy, workdir)
    }

    /// Write supervisor CA certificate and bundle into `/run/openshell/tls`
    /// (visible read-only at `/etc/openshell-tls` inside the workload).
    pub fn install_ca_material(
        &self,
        cert_pem: &[u8],
        bundle_pem: &[u8],
    ) -> io::Result<(PathBuf, PathBuf)> {
        fs::create_dir_all(RUNTIME_TLS_DIR)?;
        let cert_path = Path::new(RUNTIME_TLS_DIR).join("ca.crt");
        let bundle_path = Path::new(RUNTIME_TLS_DIR).join("ca-bundle.crt");
        write_atomic(&cert_path, cert_pem, 0o644)?;
        write_atomic(&bundle_path, bundle_pem, 0o644)?;
        Ok((
            Path::new(WORKLOAD_TLS_DIR).join("ca.crt"),
            Path::new(WORKLOAD_TLS_DIR).join("ca-bundle.crt"),
        ))
    }

    /// Freeze the runtime-owned workload cgroup. Returns `true` if frozen.
    pub fn freeze_workload(&self) -> bool {
        if !self.standing_freeze {
            return false;
        }
        let freeze_file = Path::new(WORKLOAD_CGROUP_DIR).join("cgroup.freeze");
        if fs::write(&freeze_file, "1\n").is_err() {
            return false;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Ok(events) =
                fs::read_to_string(Path::new(WORKLOAD_CGROUP_DIR).join("cgroup.events"))
                && events.lines().any(|line| line.trim() == "frozen 1")
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// Thaw the runtime-owned workload cgroup.
    pub fn thaw_workload(&self) {
        if self.standing_freeze {
            let _ = fs::write(Path::new(WORKLOAD_CGROUP_DIR).join("cgroup.freeze"), "0\n");
        }
    }

    /// Kill every process in the workload cgroup (and terminate the holder).
    pub fn kill_workload(&self) {
        let kill_file = Path::new(WORKLOAD_CGROUP_DIR).join("cgroup.kill");
        if kill_file.exists() {
            let _ = fs::write(&kill_file, "1\n");
        }
        self.thaw_workload();
        self.placement.terminate_holder();
    }

    /// Build the confirmation audit evidence validated by the supervisor.
    #[must_use]
    pub fn audit_evidence(&self, broker_healthy: bool) -> PrivilegedSandboxAuditEvidence {
        // SAFETY: PR_GET_DUMPABLE reads one scalar process property.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0;
        // SAFETY: zeroed rlimit struct populated by getrlimit(RLIMIT_CORE).
        let core_limit_zero = unsafe {
            let mut rl: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_CORE, &raw mut rl) == 0 && rl.rlim_cur == 0
        };
        PrivilegedSandboxAuditEvidence {
            profile: self.profile,
            runtime_uid: nix::unistd::geteuid().as_raw(),
            workload_uid: 0,
            sandbox_dumpable: dumpable,
            core_limit_zero,
            native_architecture: self.native_architecture.clone(),
            kernel_release: self.kernel_release.clone(),
            separate_workload_root: true,
            bpf_lsm_sealed: true,
            bpf_policy_enforced: true,
            init_net_isolated: self.init_net_isolated,
            vsock_blocked: true,
            network_mediation: broker_healthy,
            seccomp_addfd_send: self.seccomp_addfd_send,
            standing_freeze: self.standing_freeze,
            landlock_applied: false,
        }
    }
}

fn write_atomic(path: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(content)?;
    file.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)
}

fn read_utsname() -> (String, String) {
    // SAFETY: zeroed utsname passed to libc::uname.
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&raw mut uts) != 0 {
            return ("unknown".to_string(), std::env::consts::ARCH.to_string());
        }
        let to_str = |buf: &[libc::c_char]| {
            let bytes: Vec<u8> = buf
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c.to_ne_bytes()[0])
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        (to_str(&uts.release), to_str(&uts.machine))
    }
}
