// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Boot-once BPF LSM loader, policy map updater, and ringbuf telemetry reader.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use aya::maps::{Array, HashMap as BpfHashMap, RingBuf};
use aya::programs::{Lsm, lsm::LsmLink};
use aya::{Btf, Ebpf, Pod};
use openshell_core::policy::SandboxPolicy;
use openshell_ocsf::{
    ActionId, ActivityId, ConfidenceId, DetectionFindingBuilder, DispositionId, FindingInfo,
    Process, ProcessActivityBuilder, SeverityId, StatusId, ocsf_emit,
};
use tokio::io::unix::AsyncFd;

use super::path_view::stat_in_root;

const BPF_MAP_FREEZE: libc::c_long = 22;

const FS_RULE_RW: u32 = 1;
const FS_RULE_RO: u32 = 2;

const EVT_EXEC: u32 = 1;
const EVT_DENY_SEAL: u32 = 2;
const EVT_DENY_FS: u32 = 3;
const EVT_DENY_PROC: u32 = 4;
const EVT_TASK_EXIT: u32 = 5;

static BPF_OBJECT_BYTES: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/openshell_lsm.bpf.o"));

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SealConfig {
    pub active: u32,
    pub shim_tgid: u32,
    pub launcher_tgid: u32,
    pub runtime_sb_dev: u32,
    pub runtime_root_dev: u32,
    pub init_net_inum: u32,
    pub freezer_cgroup_ino: u64,
    pub cgroup_sb_dev: u32,
    pub guest_parent_tgid: u32,
}

// SAFETY: `SealConfig` is a plain C-layout struct matching `struct seal_config`
// in `bpf/openshell_lsm.bpf.c` with no padding invariants.
unsafe impl Pod for SealConfig {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PolicyConfig {
    fs_enabled: u32,
    proc_enabled: u32,
    proc_default_deny: u32,
    _pad: u32,
}

// SAFETY: `PolicyConfig` is a plain C-layout struct matching `struct policy_config`.
unsafe impl Pod for PolicyConfig {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct InodeKey {
    dev: u32,
    _pad: u32,
    ino: u64,
}

// SAFETY: `InodeKey` is a plain C-layout struct matching `struct inode_key`.
unsafe impl Pod for InodeKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TelemetryEvent {
    event_type: u32,
    reason: u32,
    pid: u32,
    tgid: u32,
    ppid: u32,
    uid: u32,
    dev: u32,
    _pad: u32,
    ino: u64,
    comm: [u8; 16],
}

/// Convert userspace `stat().st_dev` into Linux kernel `super_block->s_dev`
/// (`MKDEV(major, minor) = (major << 20) | minor`).
#[must_use]
pub fn kernel_dev(st_dev: u64) -> u32 {
    let major = libc::major(st_dev);
    let minor = libc::minor(st_dev);
    (major << 20) | minor
}

fn freeze_map_fd(fd: i32) -> io::Result<()> {
    #[repr(C)]
    struct BpfMapFreezeAttr {
        map_fd: u32,
    }
    let attr = BpfMapFreezeAttr {
        map_fd: u32::try_from(fd)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative bpf map fd"))?,
    };
    // SAFETY: `SYS_bpf(BPF_MAP_FREEZE, ...)` reads only `map_fd` from `attr`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_FREEZE,
            &raw const attr,
            size_of::<BpfMapFreezeAttr>(),
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Owns the loaded BPF LSM programs, links (held open by guest PID 1), and maps.
pub struct BpfLsmHandle {
    ebpf: Ebpf,
    _links: Vec<LsmLink>,
    tracked_fs_keys: Vec<InodeKey>,
}

const LSM_HOOKS: &[(&str, &str)] = &[
    ("openshell_lsm_bpf", "bpf"),
    ("openshell_lsm_ptrace", "ptrace_access_check"),
    ("openshell_lsm_perf", "perf_event_alloc"),
    ("openshell_lsm_task_kill", "task_kill"),
    ("openshell_lsm_task_setrlimit", "task_setrlimit"),
    ("openshell_lsm_socket_create", "socket_create"),
    ("openshell_lsm_sb_remount", "sb_remount"),
    ("openshell_lsm_sb_umount", "sb_umount"),
    ("openshell_lsm_locked_down", "locked_down"),
    ("openshell_lsm_file_open", "file_open"),
    ("openshell_lsm_inode_create", "inode_create"),
    ("openshell_lsm_inode_unlink", "inode_unlink"),
    ("openshell_lsm_inode_rename", "inode_rename"),
    ("openshell_lsm_inode_setattr", "inode_setattr"),
    ("openshell_lsm_sb_mount", "sb_mount"),
    ("openshell_lsm_bprm_check", "bprm_check_security"),
    ("openshell_lsm_task_alloc", "task_alloc"),
    ("openshell_lsm_task_free", "task_free"),
];

impl BpfLsmHandle {
    /// Load, attach, arm, and freeze the boot-once BPF LSM program.
    pub fn load_and_seal(mut cfg: SealConfig) -> anyhow::Result<Self> {
        let btf = Btf::from_sys_fs()
            .map_err(|e| anyhow::anyhow!("read /sys/kernel/btf/vmlinux for BPF LSM: {e}"))?;
        let mut ebpf = aya::EbpfLoader::new()
            .allow_unsupported_maps()
            .load(BPF_OBJECT_BYTES)
            .map_err(|e| anyhow::anyhow!("load openshell BPF LSM object: {e}"))?;

        let mut links = Vec::with_capacity(LSM_HOOKS.len());
        for &(prog_name, hook_name) in LSM_HOOKS {
            let program = ebpf
                .program_mut(prog_name)
                .ok_or_else(|| anyhow::anyhow!("missing BPF LSM program '{prog_name}'"))?;
            let lsm: &mut Lsm = program
                .try_into()
                .map_err(|e| anyhow::anyhow!("program '{prog_name}' is not an LSM program: {e}"))?;
            lsm.load(hook_name, &btf)
                .map_err(|e| anyhow::anyhow!("load BPF LSM hook '{hook_name}': {e}"))?;
            let link_id = lsm
                .attach()
                .map_err(|e| anyhow::anyhow!("attach BPF LSM hook '{hook_name}': {e}"))?;
            let link = lsm
                .take_link(link_id)
                .map_err(|e| anyhow::anyhow!("take BPF LSM link '{hook_name}': {e}"))?;
            links.push(link);
        }

        // Measure our true root-PID-namespace TGID and parent TGID from inside
        // the kernel via `openshell_lsm_bpf` before arming and freezing
        // `seal_cfg`. This works both when running as guest PID 1
        // (libkrun/Firecracker) and inside a child PID namespace (Kata
        // Containers on Kubernetes, where `kata-agent` is our parent task).
        let (kernel_tgid, guest_parent_tgid) = {
            let map = ebpf
                .map("shim_id")
                .ok_or_else(|| anyhow::anyhow!("missing shim_id BPF map"))?;
            let array: Array<_, u32> =
                Array::try_from(map).map_err(|e| anyhow::anyhow!("open shim_id BPF array: {e}"))?;
            // First lookup triggers lsm/bpf (which populates shim_id[0..2]);
            // subsequent lookups read back the recorded kernel TGIDs.
            let _ = array.get(&0, 0);
            let tgid = array
                .get(&0, 0)
                .map_err(|e| anyhow::anyhow!("read shim_id[0] BPF array: {e}"))?;
            let parent_tgid = array
                .get(&1, 0)
                .map_err(|e| anyhow::anyhow!("read shim_id[1] BPF array: {e}"))?;
            (tgid, parent_tgid)
        };
        if kernel_tgid == 0 {
            anyhow::bail!("BPF LSM failed to record kernel shim TGID");
        }
        cfg.shim_tgid = kernel_tgid;
        cfg.guest_parent_tgid = if kernel_tgid > 1 {
            guest_parent_tgid
        } else {
            0
        };
        cfg.active = 1;
        {
            let map = ebpf
                .map_mut("seal_cfg")
                .ok_or_else(|| anyhow::anyhow!("missing seal_cfg BPF map"))?;
            let mut array: Array<_, SealConfig> = Array::try_from(map)
                .map_err(|e| anyhow::anyhow!("open seal_cfg BPF array: {e}"))?;
            array
                .set(0, cfg, 0)
                .map_err(|e| anyhow::anyhow!("write seal_cfg BPF map: {e}"))?;
        }
        {
            let map = ebpf
                .map("seal_cfg")
                .ok_or_else(|| anyhow::anyhow!("missing seal_cfg BPF map"))?;
            let aya::maps::Map::Array(data) = map else {
                anyhow::bail!("seal_cfg BPF map is not an array");
            };
            let info = data
                .info()
                .map_err(|e| anyhow::anyhow!("read seal_cfg BPF map info: {e}"))?;
            let map_fd = info
                .fd()
                .map_err(|e| anyhow::anyhow!("open seal_cfg BPF map fd: {e}"))?;
            freeze_map_fd(map_fd.as_fd().as_raw_fd())
                .map_err(|e| anyhow::anyhow!("freeze seal_cfg BPF map: {e}"))?;
        }

        tracing::info!(
            hooks = links.len(),
            shim_tgid = cfg.shim_tgid,
            runtime_sb_dev = cfg.runtime_sb_dev,
            init_net_inum = cfg.init_net_inum,
            freezer_cgroup_ino = cfg.freezer_cgroup_ino,
            "boot-once BPF LSM seal armed and frozen"
        );

        Ok(Self {
            ebpf,
            _links: links,
            tracked_fs_keys: Vec::new(),
        })
    }

    /// Populate or live-reload `filesystem_policy` and `process` rules in the
    /// BPF LSM maps from `policy`.
    pub fn apply_policy(
        &mut self,
        workload_root: &Path,
        policy: &SandboxPolicy,
        workdir: &str,
    ) -> anyhow::Result<usize> {
        let mut entries: Vec<(InodeKey, u32)> = Vec::new();
        for ro_path in &policy.filesystem.read_only {
            if let Ok((st_dev, st_ino)) = stat_in_root(workload_root, ro_path) {
                entries.push((
                    InodeKey {
                        dev: kernel_dev(st_dev),
                        _pad: 0,
                        ino: st_ino,
                    },
                    FS_RULE_RO,
                ));
            }
        }
        let mut rw_paths: Vec<PathBuf> = policy.filesystem.read_write.clone();
        if !workdir.is_empty() && !rw_paths.iter().any(|p| p == Path::new(workdir)) {
            rw_paths.push(PathBuf::from(workdir));
        }
        for rw_path in &rw_paths {
            if let Ok((st_dev, st_ino)) = stat_in_root(workload_root, rw_path) {
                entries.push((
                    InodeKey {
                        dev: kernel_dev(st_dev),
                        _pad: 0,
                        ino: st_ino,
                    },
                    FS_RULE_RW,
                ));
            }
        }

        // Remove stale entries before inserting the new snapshot so live reload
        // drops removed rules without leaving orphans.
        let new_keys: Vec<InodeKey> = entries.iter().map(|(k, _)| *k).collect();
        let stale: Vec<InodeKey> = self
            .tracked_fs_keys
            .iter()
            .copied()
            .filter(|old| !new_keys.contains(old))
            .collect();

        {
            let map = self
                .ebpf
                .map_mut("fs_rules")
                .ok_or_else(|| anyhow::anyhow!("missing fs_rules BPF map"))?;
            let mut fs_map: BpfHashMap<_, InodeKey, u32> = BpfHashMap::try_from(map)
                .map_err(|e| anyhow::anyhow!("open fs_rules BPF map: {e}"))?;
            for key in stale {
                let _ = fs_map.remove(&key);
            }
            for &(key, verdict) in &entries {
                fs_map
                    .insert(key, verdict, 0)
                    .map_err(|e| anyhow::anyhow!("insert fs_rules BPF entry: {e}"))?;
            }
        }
        self.tracked_fs_keys = new_keys;

        let fs_enabled = u32::from(!policy.filesystem.read_only.is_empty());
        {
            let map = self
                .ebpf
                .map_mut("policy_cfg")
                .ok_or_else(|| anyhow::anyhow!("missing policy_cfg BPF map"))?;
            let mut array: Array<_, PolicyConfig> = Array::try_from(map)
                .map_err(|e| anyhow::anyhow!("open policy_cfg BPF map: {e}"))?;
            array
                .set(
                    0,
                    PolicyConfig {
                        fs_enabled,
                        proc_enabled: 0,
                        proc_default_deny: 0,
                        _pad: 0,
                    },
                    0,
                )
                .map_err(|e| anyhow::anyhow!("update policy_cfg BPF map: {e}"))?;
        }

        tracing::info!(
            rules = entries.len(),
            fs_enabled = fs_enabled != 0,
            "updated BPF LSM filesystem policy map"
        );
        Ok(entries.len())
    }

    /// Spawn a background tokio task that drains kernel-sourced telemetry from
    /// the BPF ringbuf and emits OCSF events.
    pub fn spawn_telemetry_reader(&mut self) -> anyhow::Result<()> {
        let Some(map) = self.ebpf.take_map("telemetry_rb") else {
            return Ok(());
        };
        let ring = RingBuf::try_from(map)
            .map_err(|e| anyhow::anyhow!("open telemetry_rb BPF ringbuf: {e}"))?;
        // SAFETY: `ring` owns its valid BPF ringbuf file descriptor for the
        // entire lifetime of `async_fd`.
        let async_fd = unsafe { AsyncFd::register(ring) }
            .map_err(|e| anyhow::anyhow!("register telemetry_rb with tokio: {e}"))?;
        tokio::spawn(async move {
            let mut async_fd = async_fd;
            loop {
                let Ok(mut guard) = async_fd.readable_mut().await else {
                    break;
                };
                while let Some(item) = guard.get_inner_mut().next() {
                    if item.len() >= size_of::<TelemetryEvent>() {
                        // SAFETY: `TelemetryEvent` is a plain `#[repr(C)]` POD
                        // written by the BPF ringbuf producer; `read_unaligned`
                        // handles any ringbuf buffer alignment.
                        let evt = unsafe {
                            std::ptr::read_unaligned(item.as_ptr().cast::<TelemetryEvent>())
                        };
                        emit_telemetry_ocsf(&evt);
                    }
                }
                guard.clear_ready();
            }
        });
        Ok(())
    }
}

fn emit_telemetry_ocsf(evt: &TelemetryEvent) {
    let nul = evt
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(evt.comm.len());
    let comm = String::from_utf8_lossy(&evt.comm[..nul]).into_owned();
    let proc_info = Process::new(&comm, i64::from(evt.tgid));
    let actor = Process::new("openshell-sandbox", i64::from(std::process::id()));

    match evt.event_type {
        EVT_EXEC => {
            let event = ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Open)
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .process(proc_info)
                .actor_process(actor)
                .message(format!(
                    "bpf-lsm exec pid={} ppid={} uid={} comm={comm} ino={}",
                    evt.tgid, evt.ppid, evt.uid, evt.ino
                ))
                .build();
            ocsf_emit!(event);
        }
        EVT_TASK_EXIT => {
            let event = ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Close)
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .process(proc_info)
                .actor_process(actor)
                .message(format!(
                    "bpf-lsm exit pid={} ppid={} uid={} comm={comm}",
                    evt.tgid, evt.ppid, evt.uid
                ))
                .build();
            ocsf_emit!(event);
        }
        EVT_DENY_SEAL => {
            let finding = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Open)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::High)
                .confidence(ConfidenceId::High)
                .is_alert(true)
                .finding_info(FindingInfo::new(
                    "sandbox-bpf-lsm-seal-denied",
                    "BPF LSM shim seal violation",
                ))
                .message(format!(
                    "bpf-lsm seal denied reason={} pid={} uid={} comm={comm} dev={} ino={}",
                    evt.reason, evt.tgid, evt.uid, evt.dev, evt.ino
                ))
                .build();
            ocsf_emit!(finding);
        }
        EVT_DENY_FS | EVT_DENY_PROC => {
            let kind = if evt.event_type == EVT_DENY_FS {
                "filesystem"
            } else {
                "process"
            };
            let event = ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Open)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .status(StatusId::Failure)
                .process(proc_info)
                .actor_process(actor)
                .message(format!(
                    "bpf-lsm {kind} policy denied rule={} pid={} uid={} comm={comm} dev={} ino={}",
                    evt.reason, evt.tgid, evt.uid, evt.dev, evt.ino
                ))
                .build();
            ocsf_emit!(event);
        }
        _ => {}
    }
}
