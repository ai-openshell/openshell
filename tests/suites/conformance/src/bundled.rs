// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reuse nextest's build metadata with this executable as
//! the only test binary. Never enter this scheduler for libtest invocations.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus, Stdio};

use testkit::program::RunOptions;
use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};

macro_rules! payload {
    ($name:literal) => {
        concat!(env!("OPENSHELL_CONFORMANCE_BUNDLE"), "/", $name)
    };
}

// Keep the payload out of the async state machine, which otherwise embeds
// identical byte strings in multiple optimized paths.
#[inline(never)]
fn materialize(root: &Path) -> io::Result<()> {
    fs::write(root.join("Cargo.toml"), "[workspace]\n")?;
    fs::write(
        root.join("cargo-metadata.json"),
        include_bytes!(payload!("cargo-metadata.json")),
    )?;
    fs::write(
        root.join("binaries-metadata.json"),
        include_bytes!(payload!("binaries-metadata.json")),
    )?;
    // Close the writable descriptor before executing (Linux rejects ETXTBSY).
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(root.join("cargo-nextest"))?
        .write_all(include_bytes!(payload!("cargo-nextest")))?;
    Ok(())
}

pub(crate) fn run(options: RunOptions) -> ExitCode {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|runtime| runtime.block_on(run_nextest(options)));
    match result {
        Ok(status) => ExitCode::from(
            status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(2),
        ),
        Err(error) => {
            eprintln!("openshell-conformance: bundled nextest: {error}");
            ExitCode::from(2)
        }
    }
}

async fn run_nextest(options: RunOptions) -> io::Result<ExitStatus> {
    let mut int = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;

    let temp = tempfile::Builder::new()
        .prefix("openshell-conformance-")
        .tempdir()?;
    let root = temp.path().canonicalize()?;
    let target = root.join("target");
    let binary = target.join(include_str!(payload!("binary-path")).trim_end());
    fs::create_dir_all(binary.parent().expect("test binary has a parent"))?;
    symlink(env::current_exe()?, &binary)?;

    materialize(&root)?;

    let config = root.join("nextest.toml");
    let report = root.join("target/nextest/default/junit.xml");
    let mut profile = format!(
        "[profile.default]\n\
         test-threads = 1\n\
         fail-fast = false\n\
         success-output = \"immediate\"\n\
         failure-output = \"immediate\"\n\
         slow-timeout = {{ period = \"{}ns\", terminate-after = 1, grace-period = \"{}ns\" }}\n",
        options.timeout.as_nanos(),
        options.grace.as_nanos()
    );
    if options.junit.is_some() {
        profile.push_str(
            "[profile.default.junit]\npath = \"junit.xml\"\nreport-skipped = \"ignored\"\nstore-success-output = true\n",
        );
    }
    fs::write(&config, profile)?;

    let mut command = Command::new(root.join("cargo-nextest"));
    command
        .args(["nextest", "run", "--cargo-metadata"])
        .arg(root.join("cargo-metadata.json"))
        .arg("--binaries-metadata")
        .arg(root.join("binaries-metadata.json"))
        .arg("--workspace-remap")
        .arg(&root)
        .arg("--target-dir-remap")
        .arg(&target)
        .arg("--config-file")
        .arg(config)
        .args([
            "--user-config-file",
            "none",
            "--no-input-handler",
            "--no-pager",
            "--profile",
            "default",
        ])
        .current_dir(&root)
        .stdin(Stdio::null())
        // The terminal sends Ctrl-C to us, not to nextest too. Nextest owns
        // the test process groups, so forward to the runner and let it reap.
        .process_group(0);
    if options.include_ignored {
        command.args(["--run-ignored", "all"]);
    }
    command.args(options.nextest_args).args(options.filters);
    let mut child = command.spawn().map_err(|error| {
        io::Error::other(format!("start runner under {}: {error}", root.display()))
    })?;
    let pid = child.id().expect("spawned child has an ID") as libc::pid_t;
    let mut interrupted = false;
    let status = loop {
        let sig = tokio::select! {
            biased;
            status = child.wait() => break status?,
            _ = int.recv() => libc::SIGINT,
            _ = term.recv() => libc::SIGTERM,
            _ = hup.recv() => libc::SIGHUP,
        };
        interrupted = true;
        // SAFETY: `wait` did not reap the child, so its PID can't be reused.
        unsafe { libc::kill(pid, sig) };
    };

    if let Some(path) = options.junit {
        // Setup/discovery errors can occur before nextest creates a report.
        if report.try_exists()? {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            fs::copy(report, &path)
                .map_err(|error| io::Error::other(format!("write {}: {error}", path.display())))?;
        } else if status.success() && !interrupted {
            return Err(io::Error::other(
                "nextest did not write the requested report",
            ));
        }
    }

    Ok(status)
}
