// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Confined lookups inside the separate workload root using `openat2(RESOLVE_IN_ROOT)`.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

const RESOLVE_IN_ROOT: u64 = 0x10;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Open `guest_path` confined to `root` via `openat2(RESOLVE_IN_ROOT)`.
pub fn open_in_root(root: &Path, guest_path: &Path, flags: i32) -> io::Result<OwnedFd> {
    let root_dir = File::open(root)?;
    let relative = guest_path.strip_prefix("/").unwrap_or(guest_path);
    let target = if relative.as_os_str().is_empty() {
        CString::new(".").expect("static dot")
    } else {
        CString::new(relative.as_os_str().as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
    };
    let how = OpenHow {
        flags: u64::try_from(flags | libc::O_CLOEXEC).unwrap_or(0),
        mode: 0,
        resolve: RESOLVE_IN_ROOT,
    };
    // SAFETY: `root_dir` is a valid open directory fd, `target` is NUL-terminated,
    // and `how` matches Linux's `struct open_how`.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_dir.as_raw_fd(),
            target.as_ptr(),
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh open descriptor owned from here.
    #[allow(clippy::cast_possible_truncation)]
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Resolve a workload path to its `(st_dev, st_ino)` confined to `root`.
pub fn stat_in_root(root: &Path, guest_path: &Path) -> io::Result<(u64, u64)> {
    let fd = open_in_root(root, guest_path, libc::O_PATH)?;
    let file = File::from(fd);
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

/// Read a bounded file inside `root` confined with `RESOLVE_IN_ROOT`.
pub fn read_to_string_in_root(
    root: &Path,
    guest_path: &Path,
    max_bytes: usize,
) -> io::Result<String> {
    use std::io::Read as _;
    let fd = open_in_root(root, guest_path, libc::O_RDONLY)?;
    let file = File::from(fd);
    let mut out = String::new();
    file.take(max_bytes as u64).read_to_string(&mut out)?;
    Ok(out)
}

/// Check whether `guest_path` is an executable regular file inside `root`.
pub fn is_executable_in_root(root: &Path, guest_path: &Path) -> bool {
    let Ok(fd) = open_in_root(root, guest_path, libc::O_PATH) else {
        return false;
    };
    let file = File::from(fd);
    let Ok(meta) = file.metadata() else {
        return false;
    };
    meta.is_file() && (meta.mode() & 0o111) != 0
}
