// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ending a launched driver when its gateway disappears.
//!
//! The gateway launches a driver and removes its socket on the next launch. A
//! gateway that is killed outside its init system would otherwise leave the
//! driver running, and the next launch would start a second one.

#[cfg(unix)]
use std::time::Duration;

/// Exit this process when its parent process ends.
///
/// The check polls the parent process id once a second, so the driver ends
/// within about a second of the gateway. It works on every unix and needs no
/// platform-specific kernel interface.
///
/// # Errors
///
/// Returns a message when the parent is already gone or the watcher cannot
/// start.
#[cfg(unix)]
pub fn die_with_parent() -> Result<(), String> {
    die_with_parent_polling(Duration::from_secs(1), || std::process::exit(1))
}

#[cfg(unix)]
fn die_with_parent_polling(
    interval: Duration,
    on_orphaned: impl FnOnce() + Send + 'static,
) -> Result<(), String> {
    let parent = std::os::unix::process::parent_id();
    if parent == 1 {
        return Err("the parent process has already ended".to_string());
    }
    std::thread::Builder::new()
        .name("parent-guard".to_string())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                if std::os::unix::process::parent_id() != parent {
                    on_orphaned();
                    return;
                }
            }
        })
        .map(|_| ())
        .map_err(|error| format!("failed to start the parent guard: {error}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_running_parent_is_not_reported() {
        let (sender, receiver) = std::sync::mpsc::channel();
        die_with_parent_polling(Duration::from_millis(10), move || {
            let _ = sender.send(());
        })
        .unwrap();
        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());
    }
}
