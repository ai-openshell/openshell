# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

ARG WORKLOAD_BASE=nvcr.io/nvidia/base/ubuntu:24.04
FROM ghcr.io/astral-sh/uv:0.12.17@sha256:10787c682e4184e4f290de1171fd4703dc63de99221f10fe1c99002ce7fa9acc AS uv
FROM ${WORKLOAD_BASE}

COPY --from=uv /uv /uvx /usr/local/bin/
# Supplied from .python-version by the build task. Test policies allow python3
# from this uv interpreter and the venv in front of it, and some tests run the
# system /usr/bin/python3 directly, so both stay.
ARG PYTHON_VERSION
# curl and openssl also support the Rust Docker tests sharing this fixture, and
# the e2e/rust OTLP relay tests export spans with requests.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git openssl python3 python-is-python3 \
    && rm -rf /var/lib/apt/lists/* \
    && if getent passwd ubuntu >/dev/null; then userdel ubuntu; fi \
    && if getent group ubuntu >/dev/null; then groupdel ubuntu; fi \
    && groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid sandbox --create-home --shell /bin/bash sandbox \
    && UV_PYTHON_INSTALL_DIR=/sandbox/.uv/python uv python install "${PYTHON_VERSION}" \
    && UV_PYTHON_INSTALL_DIR=/sandbox/.uv/python uv venv --python "${PYTHON_VERSION}" /sandbox/.venv \
    && uv pip install --python /sandbox/.venv/bin/python requests==2.32.5 \
    && chown -R sandbox:sandbox /sandbox \
    && uv cache clean

ENV VIRTUAL_ENV=/sandbox/.venv
ENV PATH="/sandbox/.venv/bin:${PATH}"
WORKDIR /sandbox
USER sandbox:sandbox
