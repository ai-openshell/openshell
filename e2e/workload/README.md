<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# E2E Python image

`Dockerfile` builds `openshell/e2e-python:dev`, the image E2E tests create
sandboxes from when they need `python3`, curl, git, openssl, or the `sandbox`
user. Build it with `mise run e2e:python-image:build`. `testkit::python_image()`
and the `e2e/rust` harness select it, and the tmachine installers load it into
every environment.

This is not a GPU workload image. Those live in [`e2e/gpu/`](../gpu/README.md)
and `mise run e2e:workloads:build` builds them.

The venv has `requests` for the `e2e/rust` OTLP relay tests; other probe
scripts use only the Python standard library. Test policies allow `python3`
from `/usr/bin`, the uv interpreter under `/sandbox/.uv/python/`, and the
`/sandbox/.venv` in front of it, so keep those paths when changing the image.
