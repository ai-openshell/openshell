// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wait policy for `sandbox exec` while its sandbox is not ready yet.
//!
//! When a shared supervisor dies or its pool rolls, the gateway hands the
//! sandbox's supervisor session to another member, and the sandbox reads
//! `Provisioning` (or `Starting`) for the ten to twenty seconds of the
//! takeover. An exec that gives up on its first observation turns that window
//! into an instant `sandbox is not ready` failure, so the CLI polls
//! `GetSandbox` and waits, within a bounded wall-clock budget, for the sandbox
//! to come back before it starts anything.
//!
//! The module is pure: it takes one decoded observation and returns a
//! decision. Clock, sleeping, transport, and jitter seeds stay with the caller,
//! matching [`crate::create_retry`].
//!
//! Only the takeover window is waitable. `Provisioning` and `Starting` can
//! reach `Ready` on their own; every other phase stops the wait with the
//! failure exec already returned, because it cannot reach `Ready` without
//! another lifecycle request: `Suspended` and `Suspending` need a resume,
//! `Stopped` needs a start, and `Completed`, `Error`, `Stopping`, `Deleting`,
//! and `Unknown` are terminal for an exec, while `Unspecified` is no
//! observation at all. This taxonomy deliberately differs from
//! `lifecycle_phase_blocks_target` in the CLI: `Stopped` blocks nothing when
//! `sandbox start` waits for `Ready`, but for exec it fails fast, and a wait on
//! a `Suspended` or `Stopping` sandbox could only burn the caller's budget.
//!
//! The wait is bounded by its wall-clock budget alone, with no attempt cap.
//! [`crate::create_retry::MAX_CREATE_ATTEMPTS`] exists because every create
//! attempt re-enters the gateway's mutation-lock wait, which holds a shared
//! connection for its whole budget; an exec-wait attempt is a cheap
//! `GetSandbox` read, so a cap could only truncate the budget the caller
//! advertised.
//!
//! The SDK's `OpenShellClient::wait_ready` classifies phases differently:
//! `Completed` is success there and a failure for exec, and `Suspending` and
//! `Suspended` are its errors. The CLI's exec path drives the raw gRPC client
//! rather than the SDK client, so the SDK keeps its behavior for now; a later
//! SDK opt-in should be expressed through this same policy so the two
//! classifications converge instead of forking a third.

use std::time::Duration;

use crate::create_retry::{backoff_floor, jitter};
use crate::proto::SandboxPhase;

/// Floor of the readiness poll interval.
pub const MIN_EXEC_WAIT_POLL: Duration = Duration::from_secs(1);

/// Ceiling of the readiness poll interval before jitter.
pub const MAX_EXEC_WAIT_POLL: Duration = Duration::from_secs(5);

/// Decision for the next `sandbox exec` readiness poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecWaitPlan {
    /// Sleep for the given duration, then observe the phase again.
    Sleep(Duration),
    /// The sandbox is ready; issue the exec.
    Proceed,
    /// The sandbox cannot reach `Ready` on its own, or the budget is spent;
    /// fail the way exec already did.
    Stop,
}

/// Whether `phase` can reach `Ready` without another lifecycle request.
///
/// Only a supervisor takeover leaves a sandbox in one of these phases on its
/// way back to `Ready`. A caller uses this to tell "waited but the budget ran
/// out" from "stopped on a phase that never had a wait".
#[must_use]
pub fn exec_wait_is_waitable(phase: SandboxPhase) -> bool {
    match phase {
        SandboxPhase::Provisioning | SandboxPhase::Starting => true,
        SandboxPhase::Unspecified
        | SandboxPhase::Ready
        | SandboxPhase::Error
        | SandboxPhase::Deleting
        | SandboxPhase::Unknown
        | SandboxPhase::Stopping
        | SandboxPhase::Stopped
        | SandboxPhase::Completed
        | SandboxPhase::Suspending
        | SandboxPhase::Suspended => false,
    }
}

/// Plan the next `sandbox exec` readiness poll.
///
/// `poll_attempt` counts the polls already slept for this exec. A waitable
/// phase sleeps one poll interval: [`MIN_EXEC_WAIT_POLL`] doubling per poll up
/// to [`MAX_EXEC_WAIT_POLL`], plus jitter of at most half the interval so the
/// hundreds of execs a takeover interrupts do not poll the recovering gateway
/// in lockstep. `seed` stretches the jitter; callers derive one per exec call
/// and keep it stable across polls. A sleep that does not fit in
/// `remaining_budget` stops instead of overrunning the caller's deadline.
#[must_use]
pub fn plan_exec_wait(
    phase: SandboxPhase,
    poll_attempt: u32,
    seed: u64,
    remaining_budget: Duration,
) -> ExecWaitPlan {
    if phase == SandboxPhase::Ready {
        return ExecWaitPlan::Proceed;
    }
    if !exec_wait_is_waitable(phase) {
        return ExecWaitPlan::Stop;
    }
    let sleep = exec_wait_poll_delay(poll_attempt, seed);
    if sleep <= remaining_budget {
        ExecWaitPlan::Sleep(sleep)
    } else {
        ExecWaitPlan::Stop
    }
}

/// Delay before the next readiness poll.
///
/// Shares the retry policy's backoff and jitter so both client loops spread a
/// recovering gateway's load the same way.
#[must_use]
pub fn exec_wait_poll_delay(poll_attempt: u32, seed: u64) -> Duration {
    let delay = backoff_floor(MIN_EXEC_WAIT_POLL, poll_attempt, MAX_EXEC_WAIT_POLL);
    delay.saturating_add(jitter(seed, poll_attempt, delay))
}

/// Suffix appended to an exec failure that ended the readiness wait.
///
/// Names the wait's elapsed wall-clock time and the last observed phase, so a
/// timeout is never read as a terminal sandbox state. The CLI appends it only
/// when the sandbox was waitable and a wait was configured.
#[must_use]
pub fn exec_wait_stopped_suffix(waited: Duration, last_phase: &str) -> String {
    format!(
        " (exec wait stopped after {}s; last observed phase: {last_phase})",
        waited.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn sleep_of(plan: ExecWaitPlan) -> Duration {
        match plan {
            ExecWaitPlan::Sleep(sleep) => sleep,
            other => panic!("expected a poll sleep, got {other:?}"),
        }
    }

    #[test]
    fn ready_proceeds_without_waiting() {
        assert_eq!(
            plan_exec_wait(SandboxPhase::Ready, 0, 7, Duration::from_mins(1)),
            ExecWaitPlan::Proceed
        );
    }

    #[test]
    fn provisioning_and_starting_wait() {
        for phase in [SandboxPhase::Provisioning, SandboxPhase::Starting] {
            let sleep = sleep_of(plan_exec_wait(phase, 0, 7, Duration::from_mins(1)));
            assert!(
                sleep >= MIN_EXEC_WAIT_POLL,
                "{phase:?}: {sleep:?} is below the poll floor"
            );
            assert!(
                sleep <= MIN_EXEC_WAIT_POLL + MIN_EXEC_WAIT_POLL / 2,
                "{phase:?}: {sleep:?} exceeds the jitter bound of the poll floor"
            );
            assert!(exec_wait_is_waitable(phase));
        }
    }

    #[test]
    fn every_other_phase_stops_immediately() {
        // Exhaustive over the proto enum: a new phase must be decided here
        // rather than silently inherit a wait or a failure.
        for phase in [
            SandboxPhase::Unspecified,
            SandboxPhase::Unknown,
            SandboxPhase::Error,
            SandboxPhase::Stopping,
            SandboxPhase::Stopped,
            SandboxPhase::Deleting,
            SandboxPhase::Completed,
            SandboxPhase::Suspending,
            SandboxPhase::Suspended,
        ] {
            assert_eq!(
                plan_exec_wait(phase, 0, 7, Duration::from_mins(1)),
                ExecWaitPlan::Stop,
                "{phase:?} cannot reach Ready on its own"
            );
            assert!(!exec_wait_is_waitable(phase), "{phase:?}");
        }
    }

    #[test]
    fn poll_delay_backs_off_to_the_cap_and_stays_jittered() {
        for (poll_attempt, floor) in [
            (0, Duration::from_secs(1)),
            (1, Duration::from_secs(2)),
            (2, Duration::from_secs(4)),
            (3, MAX_EXEC_WAIT_POLL),
            (8, MAX_EXEC_WAIT_POLL),
        ] {
            let sleep = sleep_of(plan_exec_wait(
                SandboxPhase::Provisioning,
                poll_attempt,
                7,
                Duration::from_mins(1),
            ));
            assert!(
                sleep >= floor,
                "poll {poll_attempt}: {sleep:?} is below the {floor:?} floor"
            );
            assert!(
                sleep <= floor + floor / 2,
                "poll {poll_attempt}: {sleep:?} exceeds the jitter bound of {floor:?}"
            );
        }
    }

    #[test]
    fn distinct_seeds_decorrelate_the_poll() {
        let polls: BTreeSet<Duration> = (0..64)
            .map(|seed| {
                sleep_of(plan_exec_wait(
                    SandboxPhase::Provisioning,
                    0,
                    seed,
                    Duration::from_mins(1),
                ))
            })
            .collect();
        assert!(
            polls.len() > 1,
            "every seed produced the same poll: {polls:?}"
        );
    }

    #[test]
    fn a_poll_that_does_not_fit_the_budget_stops() {
        assert_eq!(
            plan_exec_wait(SandboxPhase::Provisioning, 0, 7, Duration::ZERO),
            ExecWaitPlan::Stop,
            "a zero budget cannot cover the poll floor"
        );
        let sleep = sleep_of(plan_exec_wait(
            SandboxPhase::Provisioning,
            0,
            7,
            Duration::from_mins(1),
        ));
        assert_eq!(
            plan_exec_wait(SandboxPhase::Provisioning, 0, 7, sleep),
            ExecWaitPlan::Sleep(sleep)
        );
        let just_short = sleep.checked_sub(Duration::from_nanos(1)).unwrap();
        assert_eq!(
            plan_exec_wait(SandboxPhase::Provisioning, 0, 7, just_short),
            ExecWaitPlan::Stop
        );
    }

    #[test]
    fn stopped_suffix_names_the_budget_and_the_phase() {
        assert_eq!(
            exec_wait_stopped_suffix(Duration::from_secs(45), "Provisioning"),
            " (exec wait stopped after 45s; last observed phase: Provisioning)"
        );
    }
}
