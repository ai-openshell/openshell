# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Create or update a Cedar sandbox with configuration the CLI does not send.

The CLI sends Cedar source only. Middleware, endpoint settings, and process
identity for a Cedar policy go through the policy API, so this helper builds
the `SandboxPolicy` itself and calls the gateway with the Python SDK.

    uv run python e2e/support/cedar_sandbox.py create \
        --name NAME --policy policy.cedar --config config.yaml \
        [--provider NAME ...] [--image IMAGE] [--endpoint HOST:PORT] [-- COMMAND ...]

    uv run python e2e/support/cedar_sandbox.py update \
        --name NAME --policy policy.cedar --config config.yaml [--no-wait]

The config file is YAML with any of `network_middlewares`, `process`, and
`endpoint_settings`. An endpoint setting's `mcp.max_body_bytes` maps to the
endpoint's `json_rpc_max_body_bytes`, as it does in a YAML policy. `update`
waits until the sandbox reports the new version loaded, like `policy set
--wait`.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import yaml
from google.protobuf import json_format

from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2
from openshell.sandbox import SandboxClient

CONFIG_KEYS = {"network_middlewares", "process", "endpoint_settings"}
# Matches the CLI's default `policy set --wait` budget.
LOAD_TIMEOUT_SECS = 60.0


def _endpoint_setting(entry: dict) -> dict:
    setting = dict(entry)
    mcp = dict(setting.pop("mcp", None) or {})
    if "max_body_bytes" in mcp:
        setting["json_rpc_max_body_bytes"] = mcp.pop("max_body_bytes")
    if mcp:
        setting["mcp"] = mcp
    return setting


def build_policy(cedar_source: str, config: dict) -> sandbox_pb2.SandboxPolicy:
    unknown = set(config) - CONFIG_KEYS
    if unknown:
        raise SystemExit(f"unsupported config keys: {sorted(unknown)}")
    body: dict = {"version": 1, "cedar_policy": {"source": cedar_source}}
    if "network_middlewares" in config:
        body["network_middlewares"] = config["network_middlewares"]
    if "process" in config:
        body["process"] = config["process"]
    if "endpoint_settings" in config:
        body["endpoint_settings"] = [
            _endpoint_setting(e) for e in config["endpoint_settings"]
        ]
    return json_format.ParseDict(body, sandbox_pb2.SandboxPolicy())


def _load_policy(args: argparse.Namespace) -> sandbox_pb2.SandboxPolicy:
    config = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
    return build_policy(args.policy.read_text(encoding="utf-8"), config)


def _create(
    client: SandboxClient, args: argparse.Namespace, command: list[str]
) -> None:
    spec = openshell_pb2.SandboxSpec(
        policy=_load_policy(args),
        providers=args.provider,
        command=command or ["sleep", "infinity"],
    )
    if args.image:
        spec.template.image = args.image
    client.create(workspace=args.workspace, spec=spec, name=args.name)


def _update(client: SandboxClient, args: argparse.Namespace) -> None:
    scope = datamodel_pb2.WorkspaceSelector(workspace=args.workspace)
    response = client._stub.UpdateConfig(
        openshell_pb2.UpdateConfigRequest(
            workspace_scope=scope, sandbox=args.name, policy=_load_policy(args)
        ),
        timeout=30.0,
    )
    if args.no_wait:
        return
    deadline = time.monotonic() + LOAD_TIMEOUT_SECS
    while time.monotonic() < deadline:
        status = client._stub.GetSandboxPolicyStatus(
            openshell_pb2.GetSandboxPolicyStatusRequest(
                workspace_scope=scope, sandbox=args.name, version=response.version
            ),
            timeout=30.0,
        )
        revision = status.revision
        if revision.status == openshell_pb2.POLICY_STATUS_LOADED:
            return
        if revision.status == openshell_pb2.POLICY_STATUS_FAILED:
            raise SystemExit(
                f"policy version {response.version} failed: {revision.load_error}"
            )
        time.sleep(0.5)
    raise SystemExit(
        f"policy version {response.version} did not load in {LOAD_TIMEOUT_SECS}s"
    )


def main() -> int:
    argv = sys.argv[1:]
    command: list[str] = []
    if "--" in argv:
        split = argv.index("--")
        argv, command = argv[:split], argv[split + 1 :]
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("create", "update"):
        p = sub.add_parser(name)
        p.add_argument("--name", required=True)
        p.add_argument("--policy", required=True, type=Path)
        p.add_argument("--config", required=True, type=Path)
        p.add_argument("--workspace", default="default")
        p.add_argument(
            "--endpoint",
            help="plaintext gateway endpoint; defaults to the active gateway",
        )
        if name == "create":
            p.add_argument("--provider", action="append", default=[])
            p.add_argument("--image")
        else:
            p.add_argument("--no-wait", action="store_true")
    args = parser.parse_args(argv)

    if args.endpoint:
        endpoint = args.endpoint.removeprefix("http://").rstrip("/")
        client = SandboxClient(endpoint)
    else:
        client = SandboxClient.from_active_cluster()
    with client:
        if args.action == "create":
            _create(client, args, command)
        else:
            _update(client, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
