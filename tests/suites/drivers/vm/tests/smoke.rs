// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use testkit::Context;

fn main() -> std::process::ExitCode {
    testkit::main()
}

/// A VM gateway boots a sandbox that can run a command.
#[testkit::test]
async fn vm_sandbox_runs_a_command(cx: &mut Context) -> testkit::Result {
    cx.expect_compute_driver_identity("vm", "openshell-driver-vm")
        .await?;
    let sandbox = cx
        .sandbox("smoke")
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    sandbox.exec(["true"]).await?.success()?;
    Ok(())
}
