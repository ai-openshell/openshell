// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reuse nextest's build metadata with this executable as
//! the only test binary. Never enter this scheduler for libtest invocations.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use clap::Parser;
use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};

macro_rules! payload {
    ($name:literal) => {
        concat!(env!("OPENSHELL_CONFORMANCE_BUNDLE"), "/", $name)
    };
}

#[derive(Parser)]
#[command(
    name = "openshell-conformance run",
    about = "Run tests with bundled nextest"
)]
struct Run {
    /// Run tests whose name contains any of these.
    filters: Vec<String>,
    /// Run ignored tests too.
    #[arg(long)]
    include_ignored: bool,
    /// Maximum concurrent tests. Use more than one only on a suitable gateway.
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
    test_threads: u32,
    /// Stop each test after this many seconds.
    #[arg(long, default_value = "900", value_parser = seconds)]
    timeout: Duration,
    /// Grace period before forcibly killing a stopped test, in seconds.
    #[arg(long, default_value = "10", value_parser = seconds)]
    grace: Duration,
    /// Write a JUnit report here.
    #[arg(long, value_name = "PATH")]
    junit: Option<PathBuf>,
}

fn seconds(value: &str) -> Result<Duration, &'static str> {
    value
        .parse::<f64>()
        .ok()
        .and_then(|value| Duration::try_from_secs_f64(value).ok())
        .filter(|value| !value.is_zero())
        .ok_or("expected positive, finite seconds")
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

pub(crate) fn dispatch() -> Option<ExitCode> {
    let mut args = env::args_os().skip(1);
    if args.next()?.as_os_str() != "run" {
        return None;
    }
    let options = match Run::try_parse_from(std::iter::once("run".into()).chain(args)) {
        Ok(options) => options,
        Err(error) => {
            let _ = error.print();
            return Some(ExitCode::from(if error.use_stderr() { 2 } else { 0 }));
        }
    };
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|runtime| runtime.block_on(run(options)));
    Some(match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("openshell-conformance: bundled nextest: {error}");
            ExitCode::from(2)
        }
    })
}

async fn run(options: Run) -> io::Result<u8> {
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
            "--no-fail-fast",
            "--retries",
            "0",
            "--no-tests",
            "fail",
            "--success-output",
            "immediate",
            "--failure-output",
            "immediate",
            "--test-threads",
        ])
        .arg(options.test_threads.to_string())
        .args([
            "--run-ignored",
            if options.include_ignored {
                "all"
            } else {
                "default"
            },
        ])
        .arg("--")
        .args(options.filters)
        .current_dir(&root)
        .stdin(Stdio::null())
        // The terminal sends Ctrl-C to us, not to nextest too. Nextest owns
        // the test process groups, so forward to the runner and let it reap.
        .process_group(0);
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

    // Keep the testkit `run` exit contract rather than exposing nextest codes.
    Ok(match (interrupted, status.code()) {
        (false, Some(0)) => 0,
        (false, Some(100)) => 1,
        _ => 2,
    })
}
