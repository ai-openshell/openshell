# Chromium isolation for OpenShell — #4098

> **Design and verification work in progress.** This directory does not yet
> provide supported Chromium execution, and the existing browser probe is
> currently expected to fail. Do not use `--no-sandbox` to make it pass.

## Goal and non-negotiable invariants

Enable Chromium/Playwright with Chromium's **own user-namespace and seccomp
sandbox** while preserving the existing *agent workload* restrictions:

- Ordinary agent processes continue to lack effective and bounding
  capabilities, with `no_new_privs=1` and OpenShell seccomp enforcement.
- The workload cannot create nested user namespaces or invoke `chroot`.
- The browser cannot access supervisor credentials, gateway secrets,
  agent workspace files by default, or another sandbox's control/data.
- The browser has no direct Internet-facing interface, no host network,
  no privileged container, and no broad host mounts.
- Browser egress is mediated by OpenShell's supervisor **before** any
  destination connection; the browser cannot override DNS or proxy routes.
- Control is authenticated and bound to sandbox identity and runtime
  generation, not exposed as an unauthenticated CDP TCP listener.
- If any required enforcement cannot be established or inspected,
  provisioning fails closed. No `--no-sandbox` fallback.

The ordinary workload baseline is executable as
`e2e/rust/tests/chromium_boundary_baseline.rs` in the Podman E2E lane.

## Current evidence (not an implementation)

At OpenShell base `8ff5b6087`, the baseline Podman E2E suite passed 77
conformance tests, and the ordinary-workload nested-userns denial test passed.
In a **separate standalone Podman control**, Chromium failed with
`sys_chroot("/proc/self/fdinfo/") == 0`; direct `chroot /` also returned `EPERM`
under `--cap-drop=all --security-opt=no-new-privileges`. A nested user
namespace could be created in that standalone container, but could not make
`chroot` succeed. This is consistent with an inherited OCI seccomp decision,
not definitive proof of the specific denying layer.

In an earlier *diagnostic-only* OpenShell worktree, user namespace creation
could be made to succeed through opt-in changes, yet mount namespace creation
continued to fail with `EPERM` and Chromium reported `No usable sandbox!`.
Those opt-in changes are **not** part of the proposed production solution.

## Candidate architecture (not yet approved)

```text
  ordinary agent workload
  existing seccomp/Landlock, network=none
           |
     authenticated, sandbox-scoped browser control
           |
  isolated browser execution boundary
  no agent mounts, no supervisor secrets, no direct egress
           |
     authenticated, policy-mediated egress adapter
           |
  trusted OpenShell supervisor -> approved destination
```

Do not treat a local Chrome proxy flag as the egress security boundary.
A browser can initiate non-proxy sockets, DNS and loopback requests. The
**outer** browser network fence must prevent all unauthorized routes,
including when the browser or renderer is compromised. The egress adapter
must retain policy attribution, DNS validation, TLS/L7 rules, policy reload
semantics and audit events; inability to enforce these means fail closed.

The browser boundary also needs independent security review: Chromium requires
operations that the existing agent workload forbids. Enabling them in a new
boundary is not equivalent to proving that the boundary is secure. A Podman
sidecar may require an explicitly validated runtime profile; a microVM
implementation may instead require a separate guest. Neither is implemented
or approved by this document.

## Required implementation gates

1. **Product scope:** Maintainer acceptance that a separately managed browser
   execution boundary satisfies #4098's *in-guest* Chromium requirement.
2. **Identity and lifecycle:** Only gateway/driver-authorized sandbox sessions
   can create and access the browser. Close control connections and terminate
   the browser on stop/delete, restart or generation mismatch, and supervisor
   failure. Reconnection and cleanup must be idempotent.
3. **Filesystem and process isolation:** No supervisor secrets or implicit
   workspace mounts; non-root default, capability budget justified per
   boundary; all mount points and runtime identity verified after creation.
4. **Network and control:** No host/bridge route from the browser; authenticated
   non-public CDP bridge; every external connection governed by the same
   destination and L7 rules as the agent, including after a policy reload.
5. **Native Chromium sandbox:** Verify `chrome://sandbox` in addition to
   renderer namespace, seccomp, `NoNewPrivs` and capability state. Verify
   that Chromium does not automatically fall back to `--no-sandbox`.
6. **Adversarial tests:** Unauthorized CDP access, raw TCP/UDP/DNS egress,
   metadata/loopback access, secret and agent-file reads, policy reload,
   symlink/mount attacks, driver crash, and cross-sandbox access must fail.
7. **Runtime support:** Podman and microVM coverage per the issue, with an
   explicit unsupported-runtime error when any mandatory isolation feature
   cannot be provided.

A PR is **not complete** merely because it starts Chromium or because the
agent-workload regression test passes. Native Chromium sandbox operation,
policy-governed networking, and a real adversarial E2E pass are the merge
criteria.
