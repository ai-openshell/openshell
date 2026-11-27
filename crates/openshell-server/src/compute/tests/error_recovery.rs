// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Explicit recovery must stop retained compute before issuing a fresh launch.

use super::*;
use crate::auth::sandbox_session::PersistedSandboxIdentity;
use openshell_core::proto::ConfigurationAdmissionState;

async fn stored(runtime: &ComputeRuntime, id: &str) -> Sandbox {
    runtime
        .store
        .get_message::<Sandbox>(id)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn terminal_stop_preserves_result_when_compute_is_missing() {
    for exit_code in [0, 1, 137] {
        let driver = ControlledDriver::new();
        driver.set_stop_outcome(ControlledLifecycleOutcome::NotFound);
        let runtime = test_runtime(driver.clone()).await;
        let mut sandbox = sandbox_record("terminal-id", "terminal", SandboxPhase::Ready);
        apply_main_process_exit(&mut sandbox, "exited-instance", exit_code);
        runtime.store.put_message(&sandbox).await.unwrap();
        let session = ssh_session_record("old-session", sandbox.object_id());
        runtime.store.put_message(&session).await.unwrap();
        register_test_supervisor_session(&runtime, sandbox.object_id());

        for _ in 0..2 {
            let result = runtime.stop_sandbox("default", "terminal").await.unwrap();
            assert_eq!(result.phase(), sandbox.phase());
            assert_eq!(result.status.as_ref().unwrap().exit_code, Some(exit_code));
            assert_eq!(
                result.status.as_ref().unwrap().main_process_instance_id,
                "exited-instance"
            );
            assert_eq!(
                ready_condition(&result).unwrap().reason,
                ready_condition(&sandbox).unwrap().reason
            );
            assert_eq!(result.spec, sandbox.spec);
            assert!(!runtime.supervisor_sessions.has_session(sandbox.object_id()));
            assert!(
                runtime
                    .store
                    .get_message::<SshSession>(session.object_id())
                    .await
                    .unwrap()
                    .is_none()
            );

            let record = runtime
                .store
                .get(Sandbox::object_type(), sandbox.object_id())
                .await
                .unwrap()
                .unwrap();
            runtime
                .prune_missing_sandbox(record, openshell_core::time::now_ms(), 0)
                .await
                .unwrap();
            assert_eq!(stored(&runtime, sandbox.object_id()).await, result);
        }
        assert_eq!(driver.start_calls(), 0);
        assert_eq!(driver.delete_calls(), 0);
    }
}

#[tokio::test]
async fn terminal_stop_recovers_from_persisted_result_after_restart_or_pruning() {
    for exit_code in [0, 1, 137] {
        for startup in [false, true] {
            let driver = ControlledDriver::new();
            driver.set_stop_outcome(ControlledLifecycleOutcome::NotFound);
            let runtime = test_runtime(driver).await;
            let mut sandbox = sandbox_record("terminal-id", "terminal", SandboxPhase::Ready);
            apply_main_process_exit(&mut sandbox, "exited-instance", exit_code);
            runtime.store.put_message(&sandbox).await.unwrap();
            let terminal = stored(&runtime, sandbox.object_id()).await;
            // Simulate a gateway dying after persisting Stopping, with no
            // in-memory pre-stop snapshot available to either recovery path.
            runtime
                .write_lifecycle_phase(
                    &terminal,
                    SandboxPhase::Stopping,
                    "StopRequested",
                    "Stop requested",
                )
                .await
                .unwrap();
            let session = ssh_session_record("old-session", sandbox.object_id());
            runtime.store.put_message(&session).await.unwrap();
            register_test_supervisor_session(&runtime, sandbox.object_id());

            if startup {
                runtime
                    .recover_persisted_lifecycle_transitions()
                    .await
                    .unwrap();
            } else {
                let record = runtime
                    .store
                    .get(Sandbox::object_type(), sandbox.object_id())
                    .await
                    .unwrap()
                    .unwrap();
                runtime
                    .prune_missing_sandbox(record, openshell_core::time::now_ms(), 0)
                    .await
                    .unwrap();
            }
            let result = stored(&runtime, sandbox.object_id()).await;
            assert_eq!(result.phase(), terminal.phase());
            assert_eq!(result.status.as_ref().unwrap().exit_code, Some(exit_code));
            assert_eq!(
                ready_condition(&result).unwrap().reason,
                ready_condition(&terminal).unwrap().reason
            );
            assert!(!runtime.supervisor_sessions.has_session(sandbox.object_id()));
            assert!(
                runtime
                    .store
                    .get_message::<SshSession>(session.object_id())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[tokio::test]
async fn terminal_stop_keeps_uncertain_compute_pending_until_explicit_retry() {
    let driver = ControlledDriver::new();
    driver.set_stop_outcome(ControlledLifecycleOutcome::NotFound);
    driver.set_get_outcome(ControlledGetOutcome::Error("lookup unavailable"));
    let runtime = test_runtime(driver.clone()).await;
    let mut sandbox = sandbox_record("terminal-id", "terminal", SandboxPhase::Ready);
    apply_main_process_exit(&mut sandbox, "exited-instance", 0);
    runtime.store.put_message(&sandbox).await.unwrap();

    assert_eq!(
        runtime
            .stop_sandbox("default", "terminal")
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    let pending = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(pending.phase(), SandboxPhase::Stopping as i32);
    assert_eq!(pending.status.as_ref().unwrap().exit_code, Some(0));
    runtime
        .recover_persisted_lifecycle_transitions()
        .await
        .unwrap();
    assert_eq!(stored(&runtime, sandbox.object_id()).await, pending);

    driver.set_get_outcome(ControlledGetOutcome::Missing);
    let result = runtime.stop_sandbox("default", "terminal").await.unwrap();
    assert_eq!(result.phase(), SandboxPhase::Completed as i32);
    assert_eq!(result.status.as_ref().unwrap().exit_code, Some(0));
}

#[tokio::test]
async fn terminal_stop_recovery_does_not_overwrite_concurrent_changes() {
    let driver = ControlledDriver::new();
    driver.set_stop_outcome(ControlledLifecycleOutcome::NotFound);
    driver.block_get();
    let runtime = test_runtime(driver.clone()).await;
    let mut sandbox = sandbox_record("terminal-id", "terminal", SandboxPhase::Ready);
    apply_main_process_exit(&mut sandbox, "exited-instance", 0);
    runtime.store.put_message(&sandbox).await.unwrap();
    let stop = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.stop_sandbox("default", "terminal").await })
    };
    driver.get_started.notified().await;
    let pending = stored(&runtime, sandbox.object_id()).await;
    let deleting = runtime
        .write_lifecycle_phase(
            &pending,
            SandboxPhase::Deleting,
            "DeleteRequested",
            "Delete requested",
        )
        .await
        .unwrap();
    driver.release_get();

    assert!(stop.await.unwrap().is_err());
    assert_eq!(stored(&runtime, sandbox.object_id()).await, deleting);
}

#[tokio::test]
async fn stop_without_terminal_result_still_reports_missing_compute() {
    let driver = ControlledDriver::new();
    driver.set_stop_outcome(ControlledLifecycleOutcome::NotFound);
    let runtime = test_runtime(driver).await;
    let sandbox = sandbox_record("running-id", "running", SandboxPhase::Ready);
    runtime.store.put_message(&sandbox).await.unwrap();
    assert_eq!(
        runtime
            .stop_sandbox("default", "running")
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    let pending = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(pending.phase(), SandboxPhase::Stopping as i32);
    assert_eq!(pending.status.as_ref().unwrap().exit_code, None);
    runtime
        .recover_persisted_lifecycle_transitions()
        .await
        .unwrap();
    assert_eq!(stored(&runtime, sandbox.object_id()).await, pending);
    let record = runtime
        .store
        .get(Sandbox::object_type(), sandbox.object_id())
        .await
        .unwrap()
        .unwrap();
    runtime
        .prune_missing_sandbox(record, openshell_core::time::now_ms(), 0)
        .await
        .unwrap();
    let failed = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(failed.phase(), SandboxPhase::Error as i32);
    assert_eq!(
        ready_condition(&failed).unwrap().reason,
        "ComputeResourceMissing"
    );
}

#[tokio::test]
async fn failed_gateway_start_can_be_stopped_and_retried() {
    let driver = ControlledDriver::new();
    driver.set_start_outcome(ControlledLifecycleOutcome::Error(
        "supervisor endpoint unavailable",
    ));
    driver.set_runtime_identity("retained-runtime");
    let mut runtime =
        test_runtime_with_gateway_managed_lifecycle(driver.clone(), "test-driver").await;
    enable_runtime_identity_binding(&mut runtime);
    let mut sandbox = sandbox_record("retained-id", "retained", SandboxPhase::Ready);
    sandbox.spec = Some(SandboxSpec {
        template: Some(SandboxTemplate {
            image: "example.test/workload:retained".into(),
            ..Default::default()
        }),
        command: vec!["sleep".into(), "3600".into()],
        ..Default::default()
    });
    sandbox.status.as_mut().unwrap().configuration_activated = Some(true);
    set_compute_runtime_binding(&mut sandbox, "retained-runtime");
    runtime.store.put_message(&sandbox).await.unwrap();

    // Exercise the production startup sweep rather than inventing its failure record.
    runtime.start_persisted_sandboxes().await.unwrap();
    let failed = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(failed.phase(), SandboxPhase::Error as i32);
    assert_eq!(ready_condition(&failed).unwrap().reason, "StartFailed");
    driver.set_start_outcome(ControlledLifecycleOutcome::Ok);
    runtime.start_persisted_sandboxes().await.unwrap();
    assert_eq!(
        driver.start_calls(),
        1,
        "gateway restart does not retry this Error"
    );
    let error = runtime
        .start_sandbox("default", "retained")
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(
        error
            .message()
            .contains("stop the sandbox before retrying start")
    );

    let session = ssh_session_record("old-session", sandbox.object_id());
    runtime.store.put_message(&session).await.unwrap();
    register_test_supervisor_session(&runtime, sandbox.object_id());
    let stopped = runtime.stop_sandbox("default", "retained").await.unwrap();
    assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32);
    assert_eq!(stopped.object_id(), sandbox.object_id());
    assert_eq!(stopped.object_workspace(), sandbox.object_workspace());
    assert_eq!(stopped.spec, sandbox.spec);
    assert_eq!(
        sandbox_compute_runtime_identity(&stopped),
        "retained-runtime"
    );
    assert_eq!(
        driver.stop_requests(),
        vec![("retained-id".into(), "retained".into())]
    );
    assert_eq!(driver.delete_calls(), 0);
    assert!(!runtime.supervisor_sessions.has_session(sandbox.object_id()));
    assert!(
        runtime
            .store
            .get_message::<SshSession>(session.object_id())
            .await
            .unwrap()
            .is_none()
    );

    let authority = test_session_authority();
    let starting = runtime
        .start_sandbox_authenticated("default", "retained", Some(&authority))
        .await
        .unwrap();
    assert_eq!(starting.phase(), SandboxPhase::Starting as i32);
    assert_eq!(starting.object_id(), sandbox.object_id());
    assert_eq!(starting.spec, sandbox.spec);
    let before =
        PersistedSandboxIdentity::read(&failed.metadata.as_ref().unwrap().annotations).unwrap();
    let after =
        PersistedSandboxIdentity::read(&starting.metadata.as_ref().unwrap().annotations).unwrap();
    assert_ne!(after.runtime_generation, before.runtime_generation);
    assert_eq!(after.auth_epoch.get(), before.auth_epoch.get() + 1);
    assert_ne!(after.gateway_token_id, before.gateway_token_id);
    assert_eq!(
        driver.start_expected_runtime_identities(),
        vec!["retained-runtime", "retained-runtime"]
    );
    let status = starting.status.as_ref().unwrap();
    assert_eq!(status.configuration_activated, Some(true));
    assert_eq!(
        status.configuration_admission.as_ref().unwrap().state,
        ConfigurationAdmissionState::Pending as i32
    );

    // A live driver and connected supervisor cannot skip fresh configuration admission.
    register_test_supervisor_session(&runtime, sandbox.object_id());
    let snapshot = ready_driver_sandbox(sandbox.object_id(), sandbox.object_name());
    driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(snapshot.clone())));
    runtime.apply_sandbox_update(snapshot).await.unwrap();
    assert_eq!(
        stored(&runtime, sandbox.object_id()).await.phase(),
        SandboxPhase::Starting as i32
    );
    assert_eq!(driver.delete_calls(), 0);
}

#[tokio::test]
async fn explicit_stop_accepts_driver_error_reasons_without_an_allowlist() {
    for reason in ["ProcessExited", "ContainerExited", "DriverSpecificFailure"] {
        let driver = ControlledDriver::new();
        let runtime = test_runtime(driver.clone()).await;
        let sandbox = error_sandbox_record("error-id", "errored", reason);
        runtime.store.put_message(&sandbox).await.unwrap();

        let stopped = runtime.stop_sandbox("default", "errored").await.unwrap();
        assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32, "{reason}");
        assert_eq!(
            driver.stop_calls(),
            1,
            "Error is not proof that compute stopped"
        );
        assert_eq!(driver.delete_calls(), 0);
    }
}

#[tokio::test]
async fn pending_driver_operation_blocks_error_recovery_without_mutation() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let mut sandbox = error_sandbox_record("pending-id", "pending", "StartFailed");
    let mut operation = provisioning_deadline::new_record(openshell_core::time::now_ms(), 300_000);
    // Even a completion timestamp cannot override an unsettled original driver
    // operation. This also fences malformed/stale timeout cleanup evidence.
    operation.timeout_time = openshell_core::time::timestamp_from_millis(300_000).ok();
    operation.cleanup_completed_time = openshell_core::time::timestamp_from_millis(320_000).ok();
    operation.driver_operation_pending = true;
    operation.driver_operation_id = "owned-operation".into();
    sandbox.status.as_mut().unwrap().provisioning = Some(operation);
    runtime.store.put_message(&sandbox).await.unwrap();
    let before = stored(&runtime, sandbox.object_id()).await;

    let error = runtime
        .stop_sandbox("default", "pending")
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("operation is still pending"));
    assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
    assert_eq!(driver.stop_calls(), 0);
    assert_eq!(driver.delete_calls(), 0);
}

#[tokio::test]
async fn timeout_stop_preserves_cleanup_and_direct_start_recovery() {
    for cleanup_complete in [false, true] {
        let driver = ControlledDriver::new();
        driver.set_start_outcome(ControlledLifecycleOutcome::NotFound);
        driver.track_compute.store(true, Ordering::SeqCst);
        let runtime = test_runtime(driver.clone()).await;
        let mut sandbox = error_sandbox_record("timeout-id", "timeout", "ProvisioningTimedOut");
        let mut operation = provisioning_deadline::new_record(0, 300_000);
        operation.timeout_time = openshell_core::time::timestamp_from_millis(300_000).ok();
        operation.cleanup_retry_time = openshell_core::time::timestamp_from_millis(310_000).ok();
        if cleanup_complete {
            operation.cleanup_completed_time =
                openshell_core::time::timestamp_from_millis(320_000).ok();
        }
        sandbox.status.as_mut().unwrap().provisioning = Some(operation);
        runtime.store.put_message(&sandbox).await.unwrap();
        let before = stored(&runtime, sandbox.object_id()).await;

        let stop = runtime.stop_sandbox("default", "timeout").await;
        if cleanup_complete {
            let stopped = stop.expect(
                "completed timeout cleanup permits an explicit stopped state for image repair",
            );
            assert_eq!(stopped.phase(), SandboxPhase::Stopped as i32);
            assert_eq!(stopped.object_id(), before.object_id());
            assert_eq!(stopped.spec, before.spec);
            assert_eq!(
                stopped.status.as_ref().unwrap().provisioning,
                before.status.as_ref().unwrap().provisioning
            );
            let repeated = runtime.stop_sandbox("default", "timeout").await.unwrap();
            assert_eq!(
                repeated, stopped,
                "the retained stopped transition is idempotent"
            );
            // Docker cleanup and its snapshot poll can both report deletion of
            // the cancelled preparation after explicit stop has returned.
            for _ in 0..2 {
                runtime.apply_deleted(sandbox.object_id()).await.unwrap();
                assert_eq!(stored(&runtime, sandbox.object_id()).await, stopped);
            }
        } else {
            let error = stop.unwrap_err();
            assert_eq!(error.code(), Code::FailedPrecondition);
            assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
        }
        assert_eq!(
            driver.stop_calls(),
            0,
            "timeout cleanup already owns reclamation"
        );

        let result = runtime.start_sandbox("default", "timeout").await;
        if cleanup_complete {
            assert_eq!(result.unwrap().phase(), SandboxPhase::Starting as i32);
            assert!(
                driver.compute_exists.load(Ordering::SeqCst),
                "start recreates the missing backend after cleanup"
            );
            assert_eq!(driver.start_calls(), 1);
        } else {
            assert_eq!(result.unwrap_err().code(), Code::FailedPrecondition);
            assert_eq!(stored(&runtime, sandbox.object_id()).await, before);
            assert_eq!(driver.start_calls(), 0);
        }
        assert_eq!(driver.delete_calls(), 0);
    }
}

#[tokio::test]
async fn reclaimed_timeout_can_still_start_directly_without_stop() {
    let driver = ControlledDriver::new();
    driver.set_start_outcome(ControlledLifecycleOutcome::NotFound);
    driver.track_compute.store(true, Ordering::SeqCst);
    let runtime = test_runtime(driver.clone()).await;
    let mut sandbox = error_sandbox_record(
        "direct-timeout-id",
        "direct-timeout",
        "ImagePreparationTimedOut",
    );
    let mut operation = provisioning_deadline::new_record(0, 300_000);
    operation.timeout_time = openshell_core::time::timestamp_from_millis(300_000).ok();
    operation.cleanup_completed_time = openshell_core::time::timestamp_from_millis(320_000).ok();
    sandbox.status.as_mut().unwrap().provisioning = Some(operation);
    runtime.store.put_message(&sandbox).await.unwrap();

    let starting = runtime
        .start_sandbox("default", "direct-timeout")
        .await
        .unwrap();
    assert_eq!(starting.phase(), SandboxPhase::Starting as i32);
    assert_eq!(starting.object_id(), sandbox.object_id());
    assert!(driver.compute_exists.load(Ordering::SeqCst));
    assert_eq!(driver.start_calls(), 1);
    assert_eq!(driver.stop_calls(), 0);
    assert_eq!(driver.delete_calls(), 0);
}

#[tokio::test]
async fn failed_error_stop_retains_retryable_state_without_claiming_success() {
    for observed_error in [false, true] {
        let driver = ControlledDriver::new();
        driver.set_stop_outcome(ControlledLifecycleOutcome::Error(
            "stop response unavailable",
        ));
        let runtime = test_runtime(driver.clone()).await;
        let sandbox = error_sandbox_record("retry-id", "retry", "ProcessExited");
        if observed_error {
            let mut snapshot = ready_driver_sandbox("retry-id", "retry");
            snapshot.status.as_mut().unwrap().conditions = vec![DriverCondition {
                r#type: "Ready".into(),
                status: "False".into(),
                reason: "ProcessExited".into(),
                message: "runtime exited".into(),
                ..Default::default()
            }];
            driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(snapshot)));
        } else {
            // A response for a different sandbox cannot settle this one's stop.
            driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(
                ready_driver_sandbox("foreign-id", "retry"),
            )));
        }
        runtime.store.put_message(&sandbox).await.unwrap();

        let error = runtime.stop_sandbox("default", "retry").await.unwrap_err();
        assert_eq!(error.code(), Code::Internal);
        let retained = stored(&runtime, sandbox.object_id()).await;
        assert_eq!(
            retained.phase(),
            if observed_error {
                SandboxPhase::Error
            } else {
                SandboxPhase::Stopping
            } as i32
        );
        assert_eq!(retained.object_id(), sandbox.object_id());
        driver.set_stop_outcome(ControlledLifecycleOutcome::Ok);
        assert_eq!(
            runtime
                .stop_sandbox("default", "retry")
                .await
                .unwrap()
                .phase(),
            SandboxPhase::Stopped as i32
        );
        assert_eq!(
            driver.stop_requests(),
            vec![("retry-id".into(), "retry".into()); 2]
        );
        assert_eq!(driver.start_calls(), 0);
        assert_eq!(driver.delete_calls(), 0);
    }
}

/// Another replica can bump the sandbox between the watch update's read and
/// its CAS. The update must retry and converge instead of dropping the
/// event with a "concurrent modification" error.
#[tokio::test]
async fn watch_update_retries_after_concurrent_replica_write() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let mut sandbox = sandbox_record("sb-retry", "sandbox-retry", SandboxPhase::Provisioning);
    let endpoint = openshell_core::proto::EndpointStatus {
        endpoint_id: "endpoint:v1:gateway".to_string(),
        host: "api.example.com".to_string(),
        ports: vec![443],
        path: "/mcp".to_string(),
        ..Default::default()
    };
    sandbox.status = Some(SandboxStatus {
        phase: SandboxPhase::Provisioning as i32,
        endpoint_statuses: vec![endpoint.clone()],
        ..Default::default()
    });
    runtime.store.put_message(&sandbox).await.unwrap();
    register_test_supervisor_session(&runtime, sandbox.object_id());
    let before = stored(&runtime, sandbox.object_id()).await;

    runtime.sandbox_update_conflict_hook.arm(1);

    runtime
        .apply_watch_event(sandbox_watch_event(ready_driver_sandbox(
            sandbox.object_id(),
            sandbox.object_name(),
        )))
        .await
        .expect("a single concurrent write must be retried, not dropped");

    assert_eq!(runtime.sandbox_update_conflict_hook.fired(), 1);
    let current = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(current.phase(), SandboxPhase::Ready as i32);
    let ready = ready_condition(&current).expect("ready condition");
    assert_eq!(ready.status, "True");
    assert_eq!(ready.reason, "DependenciesReady");
    assert_eq!(
        current.status.as_ref().unwrap().endpoint_statuses,
        vec![endpoint],
        "the gateway-owned endpoint status survives the retry"
    );
    assert!(
        current.metadata.as_ref().unwrap().resource_version
            > before.metadata.as_ref().unwrap().resource_version,
        "the converged write advances the resource version"
    );
}

/// A retry must revalidate against the fresh record. A competing write that
/// moved the sandbox to Stopped wins over a bootstrap snapshot queued
/// before the stop, so the retry must retain Stopped rather than apply the
/// stale snapshot.
#[tokio::test]
async fn watch_update_retry_revalidates_against_concurrent_transition() {
    let driver = ControlledDriver::new();
    // The stop already won: the driver no longer reports the sandbox.
    driver.set_get_outcome(ControlledGetOutcome::Missing);
    let runtime = test_runtime(driver.clone()).await;
    let sandbox = sandbox_record(
        "sb-revalidate",
        "sandbox-revalidate",
        SandboxPhase::Provisioning,
    );
    runtime.store.put_message(&sandbox).await.unwrap();

    runtime.sandbox_update_conflict_hook.arm(1);
    runtime
        .sandbox_update_conflict_hook
        .set_conflicting_phase(SandboxPhase::Stopped);

    let mut bootstrapping = ready_driver_sandbox(sandbox.object_id(), sandbox.object_name());
    let mut status = make_driver_status(make_driver_condition(
        "DependenciesNotReady",
        "old bootstrap snapshot queued before stop",
    ));
    status.conditions.push(DriverCondition {
        r#type: "Bootstrapping".to_string(),
        status: "True".to_string(),
        reason: "GenerationStarting".to_string(),
        ..Default::default()
    });
    bootstrapping.status = Some(status);

    runtime
        .apply_watch_event(sandbox_watch_event(bootstrapping))
        .await
        .expect("the retry must revalidate instead of applying the stale snapshot");

    assert_eq!(runtime.sandbox_update_conflict_hook.fired(), 1);
    let current = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(
        current.phase(),
        SandboxPhase::Stopped as i32,
        "a stale bootstrap snapshot must not revive the concurrently stopped sandbox"
    );
}

/// A conflict while the sandbox is still Starting must retry the gated path.
/// Each attempt re-queries the driver and revalidates against a fresh store
/// read, so the retry applies the live snapshot rather than the stale event
/// that was queued before the replacement generation reported Ready.
#[tokio::test]
async fn watch_update_retry_requeries_driver_during_start() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let sandbox = sandbox_record(
        "sb-start-retry",
        "sandbox-start-retry",
        SandboxPhase::Starting,
    );
    runtime.store.put_message(&sandbox).await.unwrap();
    register_test_supervisor_session(&runtime, sandbox.object_id());

    // The live driver already reports the replacement generation Ready.
    driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(
        ready_driver_sandbox(sandbox.object_id(), sandbox.object_name()),
    )));
    runtime.sandbox_update_conflict_hook.arm(1);

    // The queued event predates the replacement generation coming up.
    let mut stale = ready_driver_sandbox(sandbox.object_id(), sandbox.object_name());
    stale.status = Some(make_driver_status(make_driver_condition(
        "BackendStarting",
        "replacement generation has not reported yet",
    )));

    runtime
        .apply_watch_event(sandbox_watch_event(stale))
        .await
        .expect("a conflict in the Starting revalidation path must be retried");

    assert_eq!(runtime.sandbox_update_conflict_hook.fired(), 1);
    assert_eq!(
        driver.get_calls(),
        2,
        "the retry re-queries the driver instead of reusing the first attempt"
    );
    let current = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(
        current.phase(),
        SandboxPhase::Ready as i32,
        "the retry converges the row on the live driver snapshot"
    );
    let ready = ready_condition(&current).expect("ready condition");
    assert_eq!(ready.status, "True");
}

/// A retry must not fall back to the fast path when a competing write moved
/// the row out of the phases that trigger revalidation. Another replica can
/// promote Starting to Ready between the read and the CAS; the retry must
/// revalidate against the live driver instead of applying the stale terminal
/// event over the healthy row.
#[tokio::test]
async fn watch_update_retry_retains_ready_after_concurrent_promotion() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let sandbox = sandbox_record("sb-promoted", "sandbox-promoted", SandboxPhase::Starting);
    runtime.store.put_message(&sandbox).await.unwrap();
    register_test_supervisor_session(&runtime, sandbox.object_id());

    // The live driver already reports the sandbox healthy and Ready.
    driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(
        ready_driver_sandbox(sandbox.object_id(), sandbox.object_name()),
    )));
    runtime.sandbox_update_conflict_hook.arm(1);
    // The competing write both bumps the version and promotes the row, the way
    // another replica's supervisor-session promotion would.
    runtime
        .sandbox_update_conflict_hook
        .set_conflicting_phase(SandboxPhase::Ready);

    // The queued event predates the promotion: a terminal failure snapshot
    // that is neither a container exit nor a runtime restart.
    let mut stale = ready_driver_sandbox(sandbox.object_id(), sandbox.object_name());
    stale.status = Some(make_driver_status(make_driver_condition(
        "ImagePullBackOff",
        "failed to pull the sandbox image",
    )));

    runtime
        .apply_watch_event(sandbox_watch_event(stale))
        .await
        .expect("a conflict after a concurrent promotion must be retried");

    assert_eq!(runtime.sandbox_update_conflict_hook.fired(), 1);
    let current = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(
        current.phase(),
        SandboxPhase::Ready as i32,
        "a stale terminal event must not overwrite the concurrently promoted Ready row"
    );
}

/// A continuously writing replica must not pin the watch loop: after the
/// bound the update defers to reconciliation without surfacing an error.
#[tokio::test]
async fn watch_update_defers_to_reconciliation_after_persistent_conflicts() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let sandbox = sandbox_record(
        "sb-persistent",
        "sandbox-persistent",
        SandboxPhase::Provisioning,
    );
    runtime.store.put_message(&sandbox).await.unwrap();
    let before = stored(&runtime, sandbox.object_id()).await;

    // Zero keeps the hook armed on every attempt.
    runtime.sandbox_update_conflict_hook.arm(0);

    runtime
        .apply_watch_event(sandbox_watch_event(ready_driver_sandbox(
            sandbox.object_id(),
            sandbox.object_name(),
        )))
        .await
        .expect("exhausted retries defer to reconciliation, not an error");

    assert_eq!(
        runtime.sandbox_update_conflict_hook.fired(),
        WATCH_UPDATE_CAS_RETRY_LIMIT
    );
    let current = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(
        current.phase(),
        SandboxPhase::Provisioning as i32,
        "a deferred update leaves the snapshot unapplied"
    );
    assert_eq!(current.status, before.status);
    assert_eq!(current.spec, before.spec);
    assert_eq!(
        current.metadata.as_ref().unwrap().resource_version,
        before.metadata.as_ref().unwrap().resource_version + WATCH_UPDATE_CAS_RETRY_LIMIT as u64,
        "each conflicting attempt bumped the version"
    );
}

/// Only a CAS conflict is worth retrying; a different persistence failure
/// must surface immediately after a single attempt.
#[tokio::test]
async fn watch_update_does_not_retry_non_conflict_errors() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    let sandbox = sandbox_record(
        "sb-non-conflict",
        "sandbox-non-conflict",
        SandboxPhase::Provisioning,
    );
    runtime.store.put_message(&sandbox).await.unwrap();

    runtime.sandbox_update_conflict_hook.arm_non_conflict();

    let error = runtime
        .apply_watch_event(sandbox_watch_event(ready_driver_sandbox(
            sandbox.object_id(),
            sandbox.object_name(),
        )))
        .await
        .expect_err("a non-conflict failure must not be swallowed");

    assert!(error.contains("injected non-conflict sandbox update failure"));
    assert_eq!(
        runtime.sandbox_update_conflict_hook.fired(),
        1,
        "a non-conflict error is returned after a single attempt"
    );
    assert_eq!(
        stored(&runtime, sandbox.object_id()).await.phase(),
        SandboxPhase::Provisioning as i32
    );
}

/// Watch events are applied sequentially, so a persistently conflicting
/// update must stay bounded or it would block every other sandbox.
#[tokio::test]
async fn watch_update_exhaustion_does_not_block_other_sandboxes() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    for sandbox in [
        sandbox_record(
            "sb-conflict",
            "sandbox-conflict",
            SandboxPhase::Provisioning,
        ),
        sandbox_record("sb-other", "sandbox-other", SandboxPhase::Provisioning),
    ] {
        runtime.store.put_message(&sandbox).await.unwrap();
    }
    register_test_supervisor_session(&runtime, "sb-other");
    runtime
        .sandbox_update_conflict_hook
        .arm_for("sb-conflict", 0);

    let (shutdown_tx, watch_handle) = start_watch_loop(&runtime, &driver).await;
    let mut other_rx = runtime.sandbox_watch_bus.subscribe("sb-other");

    driver.send_event(sandbox_watch_event(ready_driver_sandbox(
        "sb-conflict",
        "sandbox-conflict",
    )));
    driver.send_event(sandbox_watch_event(ready_driver_sandbox(
        "sb-other",
        "sandbox-other",
    )));

    tokio::time::timeout(Duration::from_secs(1), other_rx.recv())
        .await
        .expect("sandbox B was blocked behind sandbox A's retries")
        .expect("watch bus closed before notifying sandbox B");

    assert_eq!(
        runtime.sandbox_update_conflict_hook.fired(),
        WATCH_UPDATE_CAS_RETRY_LIMIT
    );
    assert_eq!(
        stored(&runtime, "sb-other").await.phase(),
        SandboxPhase::Ready as i32
    );
    assert_eq!(
        stored(&runtime, "sb-conflict").await.phase(),
        SandboxPhase::Provisioning as i32
    );

    stop_watch_loop(shutdown_tx, watch_handle).await;
}

/// A conflicted retry must not wait on a lifecycle gate that a slow driver
/// stop RPC holds: the sequential watch loop has to keep applying unrelated
/// sandbox events, and the deferred sandbox converges through reconciliation.
#[tokio::test]
async fn watch_update_retry_defers_when_lifecycle_gate_is_held() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver.clone()).await;
    for sandbox in [
        sandbox_record("sb-gated", "sandbox-gated", SandboxPhase::Provisioning),
        sandbox_record("sb-other", "sandbox-other", SandboxPhase::Provisioning),
    ] {
        runtime.store.put_message(&sandbox).await.unwrap();
    }
    register_test_supervisor_session(&runtime, "sb-other");
    // The first CAS attempt for sb-gated loses a race, so the retry must
    // revalidate through the gated path.
    runtime.sandbox_update_conflict_hook.arm_for("sb-gated", 1);

    // A lifecycle operation owns sb-gated's gate for the whole test, the way
    // quiesce_sandbox holds it across the driver stop RPC.
    let gate = runtime.lifecycle_gates.lock_for("sb-gated").await;
    let before = stored(&runtime, "sb-gated").await;

    let (shutdown_tx, watch_handle) = start_watch_loop(&runtime, &driver).await;
    let mut other_rx = runtime.sandbox_watch_bus.subscribe("sb-other");

    driver.send_event(sandbox_watch_event(ready_driver_sandbox(
        "sb-gated",
        "sandbox-gated",
    )));
    driver.send_event(sandbox_watch_event(ready_driver_sandbox(
        "sb-other",
        "sandbox-other",
    )));

    tokio::time::timeout(Duration::from_secs(1), other_rx.recv())
        .await
        .expect("sandbox B was blocked behind the gated sandbox's retry")
        .expect("watch bus closed before notifying sandbox B");

    assert_eq!(runtime.sandbox_update_conflict_hook.fired(), 1);
    assert_eq!(
        stored(&runtime, "sb-other").await.phase(),
        SandboxPhase::Ready as i32
    );
    let deferred = stored(&runtime, "sb-gated").await;
    assert_eq!(
        deferred.phase(),
        before.phase(),
        "the deferred retry must leave the snapshot unapplied"
    );
    assert_eq!(deferred.status, before.status);
    assert_eq!(deferred.spec, before.spec);

    // A busy gate defers without error instead of reporting a retryable
    // conflict that would re-enter the retry loop against the same gate.
    runtime
        .apply_sandbox_update_once(&ready_driver_sandbox("sb-gated", "sandbox-gated"), true)
        .await
        .expect("a busy lifecycle gate must defer the retry, not fail it");

    drop(gate);
    stop_watch_loop(shutdown_tx, watch_handle).await;
}

/// The CAS applies the stopped snapshot before the session cleanup runs. A
/// cleanup failure must therefore surface after a single attempt: retrying it
/// like a CAS conflict would re-apply the snapshot and then swallow the
/// cleanup error once the retry budget runs out.
#[tokio::test]
async fn stopped_snapshot_cleanup_failure_surfaces_without_retry() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver).await;
    let sandbox = sandbox_record(
        "sb-cleanup-failure",
        "sandbox-cleanup-failure",
        SandboxPhase::Provisioning,
    );
    runtime.store.put_message(&sandbox).await.unwrap();
    let session = ssh_session_record("stopped-session", sandbox.object_id());
    runtime.store.put_message(&session).await.unwrap();
    let before = stored(&runtime, sandbox.object_id()).await;

    // Fail the SSH session delete that runs after the CAS committed the
    // stopped snapshot, the way a store outage would.
    runtime
        .store
        .execute_for_test(
            r#"CREATE TRIGGER fail_ssh_session_cleanup BEFORE DELETE ON "objects"
               BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END"#,
        )
        .await;

    let mut stopped = ready_driver_sandbox(sandbox.object_id(), sandbox.object_name());
    stopped.status = Some(DriverSandboxStatus {
        conditions: vec![DriverCondition {
            r#type: "Suspended".to_string(),
            status: "True".to_string(),
            reason: "PodTerminated".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    });

    let error = runtime
        .apply_watch_event(sandbox_watch_event(stopped))
        .await
        .expect_err("a cleanup failure after the CAS must not be retried into a deferral");

    assert!(
        error.contains("delete sandbox SSH sessions"),
        "the cleanup failure must be reported verbatim, got: {error}"
    );
    let current = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(
        current.phase(),
        SandboxPhase::Stopped as i32,
        "the CAS already applied the stopped snapshot"
    );
    assert_eq!(
        current.metadata.as_ref().unwrap().resource_version,
        before.metadata.as_ref().unwrap().resource_version + 1,
        "the snapshot was applied exactly once"
    );
    assert!(
        runtime
            .store
            .get_message::<SshSession>(session.object_id())
            .await
            .unwrap()
            .is_some(),
        "the failed cleanup left the SSH session in place"
    );
}

/// The reconcile sweep converts a lost CAS race into the `Display` text of
/// `SandboxUpdateError`, so that wording is what operators see. It must name
/// the current resource version, and fall back to `unknown` when the store
/// does not report one.
#[test]
fn sandbox_update_conflict_display_names_the_current_resource_version() {
    assert_eq!(
        SandboxUpdateError::Conflict {
            current_resource_version: Some(42),
        }
        .to_string(),
        "concurrent modification detected during sandbox reconciliation \
         (current resource_version: 42)"
    );
    assert_eq!(
        SandboxUpdateError::Conflict {
            current_resource_version: None,
        }
        .to_string(),
        "concurrent modification detected during sandbox reconciliation \
         (current resource_version: unknown)"
    );
    assert_eq!(
        SandboxUpdateError::Other("store offline".to_string()).to_string(),
        "store offline"
    );
}

/// The reconciliation sweep applies a snapshot without the watch path's retry,
/// and reports a lost race through `SandboxUpdateError`'s `Display` text.
#[tokio::test]
async fn reconcile_reports_conflict_with_the_current_resource_version() {
    let driver = ControlledDriver::new();
    let sandbox = sandbox_record(
        "sb-reconcile-conflict",
        "sandbox-reconcile-conflict",
        SandboxPhase::Provisioning,
    );
    let polled = ready_driver_sandbox(sandbox.object_id(), sandbox.object_name());
    driver.set_get_outcome(ControlledGetOutcome::Sandbox(Box::new(polled.clone())));
    let runtime = test_runtime(driver).await;
    runtime.store.put_message(&sandbox).await.unwrap();
    let before = stored(&runtime, sandbox.object_id()).await;

    // Another replica writes between the sweep's read and its CAS.
    runtime.sandbox_update_conflict_hook.arm(1);
    let error = runtime
        .reconcile_snapshot_sandbox(polled, i64::MAX)
        .await
        .expect_err("a lost CAS race is reported to the sweep");

    let current_version = before.metadata.as_ref().unwrap().resource_version + 1;
    assert_eq!(
        error,
        format!(
            "concurrent modification detected during sandbox reconciliation \
             (current resource_version: {current_version})"
        )
    );
    assert_eq!(
        runtime.sandbox_update_conflict_hook.fired(),
        1,
        "the sweep reports the conflict instead of retrying it"
    );
}

/// A supervisor session ownership read is unrelated to the CAS, so a failure
/// there must surface immediately instead of being retried into the
/// exhaustion deferral, which would hide the store problem.
#[tokio::test]
async fn supervisor_session_read_failure_surfaces_without_retry() {
    let driver = ControlledDriver::new();
    let runtime = test_runtime(driver).await;
    let sandbox = sandbox_record(
        "sb-session-read",
        "sandbox-session-read",
        SandboxPhase::Provisioning,
    );
    runtime.store.put_message(&sandbox).await.unwrap();
    // A corrupt ownership record makes the supervisor session probe fail the
    // way a store decode error does, before the update reaches its CAS.
    runtime
        .store
        .put(
            "supervisor_session_owner",
            &format!("supervisor-owner:{}", sandbox.object_id()),
            sandbox.object_id(),
            "",
            b"not a supervisor owner payload",
            None,
        )
        .await
        .unwrap();
    let before = stored(&runtime, sandbox.object_id()).await;

    let error = runtime
        .apply_watch_event(sandbox_watch_event(ready_driver_sandbox(
            sandbox.object_id(),
            sandbox.object_name(),
        )))
        .await
        .expect_err("a session probe failure must not be deferred as a conflict");

    assert!(
        error.contains("decode error"),
        "the store failure must be reported verbatim, got: {error}"
    );
    let current = stored(&runtime, sandbox.object_id()).await;
    assert_eq!(current.phase(), SandboxPhase::Provisioning as i32);
    assert_eq!(
        current.metadata.as_ref().unwrap().resource_version,
        before.metadata.as_ref().unwrap().resource_version,
        "the update stopped before its CAS"
    );
}
