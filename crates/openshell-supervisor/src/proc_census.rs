// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cost census for the process under test, read from `/proc/self`.
//!
//! The shared-supervisor baseline test and the Linux-gated thread assertions
//! added with the shared instance runtime use these readers to count threads,
//! descriptors, sockets, and resident memory for the whole test process.
//! The supervisor binary has no use for its own census, so the module is not
//! compiled into non-test builds.
//!
//! Each reader keeps text parsing separate from the `/proc` read that supplies
//! it, so the unit tests run against fixtures and never depend on the live
//! `/proc` of the host.

use std::fs;
use std::io;
use std::path::Path;

/// Thread ID and the `comm` name the kernel reports for it.
pub type Thread = (u32, String);

/// One thread sample: the threads whose `comm` was read, and how many thread
/// IDs exited between the task directory listing and their `comm` read.
#[derive(Debug, Default)]
pub struct ThreadCensus {
    /// Threads that were still present when their `comm` was read.
    pub threads: Vec<Thread>,
    /// Thread IDs that vanished mid-sample; a churn signal, not a failure.
    pub skipped: usize,
}

const SELF_TASK: &str = "/proc/self/task";
const SELF_FD: &str = "/proc/self/fd";
const SELF_STATUS: &str = "/proc/self/status";

/// Threads in this process, sorted by thread ID, plus how many vanished
/// between the directory listing and their `comm` read.
pub fn threads() -> io::Result<ThreadCensus> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(SELF_TASK)? {
        let name = entry?.file_name();
        if let Some(tid) = parse_task_id(&name.to_string_lossy()) {
            ids.push(tid);
        }
    }
    collect_threads(ids, |tid| {
        fs::read_to_string(Path::new(SELF_TASK).join(tid.to_string()).join("comm"))
    })
}

/// Number of descriptors the process holds, read from the directory entries.
///
/// A descriptor can close between `read_dir` and the caller's use of it; the
/// count is a sample of the process, not a stable handle list. The `read_dir`
/// call itself holds a descriptor that appears in the listing, so it is not
/// counted; the cluster census reads another process's `/proc` and has no
/// such bias, which keeps the two producers comparable.
pub fn fd_count() -> io::Result<usize> {
    count_entries(Path::new(SELF_FD)).map(|count| count.saturating_sub(1))
}

/// Number of descriptors that point at a socket.
pub fn socket_count() -> io::Result<usize> {
    let mut links = Vec::new();
    for entry in fs::read_dir(SELF_FD)? {
        let entry = entry?;
        if let Ok(target) = fs::read_link(entry.path()) {
            links.push(target.to_string_lossy().into_owned());
        }
    }
    Ok(count_sockets(links.iter().map(String::as_str)))
}

/// Resident set size in KiB, or `None` when the kernel omits `VmRSS`.
pub fn vm_rss_kib() -> io::Result<Option<u64>> {
    Ok(parse_vm_rss_kib(&fs::read_to_string(SELF_STATUS)?))
}

fn parse_task_id(name: &str) -> Option<u32> {
    name.parse().ok()
}

fn collect_threads(
    ids: impl IntoIterator<Item = u32>,
    mut comm: impl FnMut(u32) -> io::Result<String>,
) -> io::Result<ThreadCensus> {
    let mut census = ThreadCensus::default();
    for tid in ids {
        match comm(tid) {
            Ok(text) => census.threads.push((tid, parse_comm(&text))),
            // The thread exited between the directory listing and this read.
            // That churn is what the census exists to observe, so the tid is
            // counted and skipped rather than failing the sample.
            Err(error) if error.kind() == io::ErrorKind::NotFound => census.skipped += 1,
            Err(error) => return Err(error),
        }
    }
    census.threads.sort_unstable();
    Ok(census)
}

fn parse_comm(text: &str) -> String {
    text.trim_end_matches('\n').to_string()
}

fn count_entries(dir: &Path) -> io::Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(dir)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

fn count_sockets<'a>(links: impl IntoIterator<Item = &'a str>) -> usize {
    links
        .into_iter()
        .filter(|link| is_socket_link(link))
        .count()
}

fn is_socket_link(link: &str) -> bool {
    link.starts_with("socket:[") && link.ends_with(']')
}

fn parse_vm_rss_kib(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let value = line.strip_prefix("VmRSS:")?;
        value.split_whitespace().next()?.parse().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numeric_task_ids_and_ignores_other_names() {
        let ids: Vec<_> = ["12", "344", "not-a-thread", "7"]
            .into_iter()
            .filter_map(parse_task_id)
            .collect();
        assert_eq!(ids, [12, 344, 7]);
    }

    #[test]
    fn collects_threads_with_their_comm_names_sorted_by_tid() {
        let census = collect_threads([300, 100], |tid| Ok(format!("worker-{tid}\n"))).unwrap();
        assert_eq!(
            census.threads,
            [
                (100, "worker-100".to_string()),
                (300, "worker-300".to_string())
            ]
        );
        assert_eq!(census.skipped, 0);
    }

    #[test]
    fn collect_threads_skips_threads_that_exit_before_their_comm_read() {
        // A thread can exit between the /proc/self/task read_dir and its comm
        // read. That churn is what the census exists to observe, so the tid is
        // skipped rather than aborting the whole sample.
        let census = collect_threads([100, 200, 300], |tid| {
            if tid == 200 {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "thread exited before its comm read",
                ))
            } else {
                Ok(format!("worker-{tid}\n"))
            }
        })
        .expect("a vanished tid is churn, not an error");
        assert_eq!(
            census.threads,
            [
                (100, "worker-100".to_string()),
                (300, "worker-300".to_string())
            ]
        );
        assert_eq!(census.skipped, 1);
    }

    #[test]
    fn collect_threads_propagates_genuine_comm_read_errors() {
        let error = collect_threads([100], |_tid| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "comm unreadable",
            ))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn counts_only_socket_descriptors() {
        let links = [
            "socket:[12345]",
            "pipe:[678]",
            "/dev/null",
            "socket:[9]",
            "socket:[unterminated",
        ];
        assert_eq!(count_sockets(links), 2);
    }

    #[test]
    fn counts_directory_entries_without_touching_proc() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["stdin", "stdout", "stderr"] {
            fs::write(dir.path().join(name), b"").unwrap();
        }
        assert_eq!(count_entries(dir.path()).unwrap(), 3);
    }

    #[test]
    fn parses_vm_rss_from_a_status_fixture() {
        let status = "Name:\tsupervisor\nVmPeak:\t  900000 kB\nVmRSS:\t  12345 kB\nThreads:\t4\n";
        assert_eq!(parse_vm_rss_kib(status), Some(12345));
    }

    #[test]
    fn a_status_without_vm_rss_returns_none() {
        assert_eq!(parse_vm_rss_kib("Name:\tsupervisor\nThreads:\t4\n"), None);
    }
}
