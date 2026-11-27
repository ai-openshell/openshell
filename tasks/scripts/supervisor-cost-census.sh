#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Measure the cost of a shared supervisor at a given sandbox count.
#
# Deploys the Helm chart on a kind cluster created with the Podman provider,
# overlays the shared supervisor pool limit so N sandboxes fit, creates N idle
# sandboxes, and reads the supervisor's cost out of band: a
# `kubectl debug --target=supervisor` container shares the supervisor's
# process namespace and reads `/proc/1` directly, so the census needs no code
# inside the supervisor process. Results are JSON under
# `~/.cache/openshell/census/` (never `/tmp`, which is tmpfs on many hosts).
#
# Usage:
#   tasks/scripts/supervisor-cost-census.sh [--sandboxes N] [--keep-cluster]
#
# Environment:
#   OPENSHELL_CENSUS_SANDBOXES              Sandboxes to create (default 8).
#   OPENSHELL_CENSUS_SETTLE_SECONDS         Fixed wait before sampling (default 30).
#   OPENSHELL_CENSUS_SAMPLE_INTERVAL_SECONDS
#                                           Pause between samples (default 5).
#   OPENSHELL_CENSUS_MAX_SAMPLES            Stop after this many samples even if
#                                           the thread count never settles (default 6).
#   OPENSHELL_CENSUS_DEBUG_IMAGE            Image for the debug container
#                                           (default digest-pinned busybox 1.36;
#                                           the container runs with CAP_SYS_PTRACE
#                                           in the supervisor's process namespace,
#                                           so it runs known content).
#   OPENSHELL_CENSUS_SANDBOX_IMAGE          Passed to `sandbox create --from`.
#   OPENSHELL_CENSUS_CLUSTER                kind cluster name (default openshell-census).
#   OPENSHELL_CENSUS_KEEP_CLUSTER           Keep the kind cluster after the run.
#   OPENSHELL_CENSUS_RESULTS_DIR            Results directory.
#   OPENSHELL_E2E_KUBE_CONTEXT              Reuse this kubectl context instead of
#                                           creating a kind cluster.
#   KIND_BIN                                kind binary (default `kind`); point it
#                                           at a kind that is not on PATH.
#   KIND_EXPERIMENTAL_PROVIDER              kind provider (default podman).
#
# Pin N, the overlay, and the host when comparing before and after numbers.

set -euo pipefail

# Resolve the script path before changing directory, so the --inner
# re-invocation and usage text do not depend on the caller's cwd.
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT="$(cd "$(dirname "${SCRIPT_PATH}")/../.." && pwd)"
cd "${ROOT}"

CLUSTER_CREATED=0
CLUSTER_KEPT=0
CLUSTER_NAME=""
KIND_BIN="${KIND_BIN:-kind}"
KIND_LAUNCHER=()
KIND_ON_PATH_DIR=""
# supervisor.pool.maxInstancesPerMember set by
# deploy/helm/openshell/ci/values-supervisor-scale.yaml. The gateway refuses
# creates past this count, so a larger run fails mid-way.
MAX_SANDBOXES=256

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: $1 is required" >&2
    exit 1
  fi
}

usage() {
  sed -n '/^# Usage:/,/^# Pin N/p' "${SCRIPT_PATH}" | sed 's/^# \{0,1\}//'
}

cleanup_cluster() {
  if [[ -n "${KIND_ON_PATH_DIR}" ]]; then
    rm -rf "${KIND_ON_PATH_DIR}"
  fi
  if [[ "${CLUSTER_CREATED}" == "1" && "${CLUSTER_KEPT}" != "1" ]]; then
    echo "Deleting kind cluster ${CLUSTER_NAME}..."
    "${KIND_LAUNCHER[@]+"${KIND_LAUNCHER[@]}"}" "${KIND_BIN}" delete cluster \
      --name "${CLUSTER_NAME}" || true
  fi
}

# Helm values layered on the chart, in order: the shared supervisor topology,
# the raised pool limit, then the client TLS the shared supervisor requires.
census_overlay() {
  printf '%s' \
    "${ROOT}/deploy/helm/openshell/ci/values-supervisor.yaml:${ROOT}/deploy/helm/openshell/ci/values-supervisor-scale.yaml:${ROOT}/deploy/helm/openshell/ci/values-tls-port-forward.yaml"
}

# Emit the census from inside a container that shares the supervisor's process
# namespace. Every line is prefixed with `CENSUS ` so the host can drop any
# kubectl noise from the captured output.
census_remote_script() {
  cat <<'REMOTE'
set -euo pipefail
# Give `kubectl debug --attach` time to connect before the container exits.
sleep 2
status=/proc/1/status
fds=/proc/1/fd
tasks=/proc/1/task
vm_rss_kib=$(awk '/^VmRSS:/ {print $2}' "$status")
fd_count=0
for _ in "$fds"/*; do fd_count=$((fd_count + 1)); done
socket_count=0
for fd in "$fds"/*; do
  link=$(readlink "$fd" 2>/dev/null || true)
  case "$link" in
    socket:\[*\]) socket_count=$((socket_count + 1)) ;;
  esac
done
table_count() {
  if [ -r "$1" ]; then
    lines=$(wc -l < "$1")
    if [ "$lines" -gt 0 ]; then
      printf '%s\n' "$((lines - 1))"
      return 0
    fi
  fi
  printf '0\n'
}
printf 'CENSUS vm_rss_kib=%s\n' "$vm_rss_kib"
printf 'CENSUS fd_count=%s\n' "$fd_count"
printf 'CENSUS socket_count=%s\n' "$socket_count"
# The /proc/1/net tables describe the whole pod network namespace, not the
# supervisor process, so their keys say so: they count TIME_WAIT sockets and
# anything else in the netns and can exceed the process-scoped socket_count.
printf 'CENSUS netns_tcp_sockets=%s\n' "$(table_count /proc/1/net/tcp)"
printf 'CENSUS netns_tcp6_sockets=%s\n' "$(table_count /proc/1/net/tcp6)"
printf 'CENSUS netns_udp_sockets=%s\n' "$(table_count /proc/1/net/udp)"
printf 'CENSUS netns_udp6_sockets=%s\n' "$(table_count /proc/1/net/udp6)"
printf 'CENSUS netns_unix_sockets=%s\n' "$(table_count /proc/1/net/unix)"
skipped_threads=0
for task in "$tasks"/*; do
  tid=${task##*/}
  # The task can exit between the directory listing and this read. That is the
  # churn the census measures, so count and skip the vanished tid instead of
  # aborting.
  name=$(cat "$task/comm" 2>/dev/null) || { skipped_threads=$((skipped_threads + 1)); continue; }
  printf 'CENSUS thread=%s\t%s\n' "$tid" "$name"
done
printf 'CENSUS skipped_threads=%s\n' "$skipped_threads"
REMOTE
}

# Sample the supervisor through an ephemeral container that targets the
# supervisor container. The custom spec runs the debug container as the
# supervisor's own non-root user, which satisfies the pod's runAsNonRoot, and
# adds CAP_SYS_PTRACE so /proc/1/fd stays readable under Yama ptrace limits.
census_sample() {
  local context="$1" namespace="$2" pod="$3" image="$4" custom="$5" script
  script="$(census_remote_script)"
  kubectl --context "${context}" -n "${namespace}" debug "pod/${pod}" \
    --target=supervisor --image="${image}" --custom="${custom}" --attach=true \
    -- sh -c "${script}" | sed -n 's/^CENSUS //p'
}

# Turn the sampled `key=value` and `thread=<tid>\t<name>` lines into JSON.
census_to_json() {
  jq -Rn '
    [inputs | select(length > 0)] as $lines
    | reduce $lines[] as $line
        ({thread_names: {}};
         if ($line | startswith("thread=")) then
           ($line | ltrimstr("thread=") | split("\t")) as $parts
           | .thread_names[$parts[0]] = $parts[1]
         else
           ($line | split("=")) as $parts
           | .[$parts[0]] = ($parts[1] | tonumber? // $parts[1])
         end)
    | . + {thread_count: (.thread_names | length)}
  '
}

run_census() {
  require_cmd kubectl
  require_cmd jq

  local count="${OPENSHELL_CENSUS_SANDBOXES:-8}"
  local settle_seconds="${OPENSHELL_CENSUS_SETTLE_SECONDS:-30}"
  local sample_interval="${OPENSHELL_CENSUS_SAMPLE_INTERVAL_SECONDS:-5}"
  local max_samples="${OPENSHELL_CENSUS_MAX_SAMPLES:-6}"
  local debug_image="${OPENSHELL_CENSUS_DEBUG_IMAGE:-busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
  local sandbox_image="${OPENSHELL_CENSUS_SANDBOX_IMAGE:-}"
  local results_dir="${OPENSHELL_CENSUS_RESULTS_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/openshell/census}"
  local context="${OPENSHELL_E2E_KUBE_CONTEXT:?the e2e wrapper must export OPENSHELL_E2E_KUBE_CONTEXT}"
  local namespace="${OPENSHELL_E2E_KUBE_NAMESPACE:?the e2e wrapper must export OPENSHELL_E2E_KUBE_NAMESPACE}"
  local release="${OPENSHELL_E2E_KUBE_RELEASE:?the e2e wrapper must export OPENSHELL_E2E_KUBE_RELEASE}"
  local cli="${OPENSHELL_BIN:-${ROOT}/target/debug/openshell}"
  local overlay run_id name pod node node_cpu raw sample_json samples
  local previous_threads threads settled attempt created result_file
  local run_as_user run_as_non_root custom_spec
  local -a names create_args

  overlay="$(census_overlay)"
  # Sandbox names are capped at 19 characters by the gateway, so the run id is
  # a hex timestamp, not a decimal epoch plus pid.
  run_id="$(printf 'c-%x' "$(date -u +%s)")"
  mkdir -p "${results_dir}"

  names=()
  for ((attempt = 1; attempt <= count; attempt += 1)); do
    name="${run_id}-${attempt}"
    create_args=(sandbox create --detach --name "${name}")
    if [[ -n "${sandbox_image}" ]]; then
      create_args+=(--from "${sandbox_image}")
    fi
    echo "Creating sandbox ${attempt}/${count}: ${name}"
    "${cli}" "${create_args[@]}" >/dev/null
    names+=("${name}")
  done
  created="${#names[@]}"

  pod="$(kubectl --context "${context}" -n "${namespace}" get pods \
    -l "app.kubernetes.io/instance=${release},app.kubernetes.io/component=supervisor" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}')"
  if [[ -z "${pod}" ]]; then
    echo "ERROR: no running supervisor pod in namespace ${namespace}" >&2
    exit 1
  fi
  node="$(kubectl --context "${context}" -n "${namespace}" get "pod/${pod}" \
    -o jsonpath='{.spec.nodeName}')"
  node_cpu="$(kubectl --context "${context}" get node "${node}" \
    -o jsonpath='{.status.capacity.cpu}')"
  # A cluster this script did not create keeps the maxPods and pod CIDR it was
  # created with (kind defaults: 110 pods, a /24 per node), so the node's real
  # pod budget gates the run instead of the overlay's pool cap. System pods
  # already occupy some of it.
  node_pod_budget="$(kubectl --context "${context}" get node "${node}" \
    -o jsonpath='{.status.allocatable.pods}')"
  if [[ -n "${node_pod_budget}" ]] \
     && (( count + 10 > node_pod_budget )); then
    echo "ERROR: node ${node} can host ${node_pod_budget} pods, leaving fewer than ${count} sandboxes plus the cluster's own pods; recreate the kind cluster with this script's node config or lower the sandbox count" >&2
    exit 1
  fi

  run_as_user="$(kubectl --context "${context}" -n "${namespace}" get "pod/${pod}" \
    -o jsonpath='{.spec.securityContext.runAsUser}')"
  run_as_non_root="$(kubectl --context "${context}" -n "${namespace}" get "pod/${pod}" \
    -o jsonpath='{.spec.securityContext.runAsNonRoot}')"
  # When the pod sets an explicit UID, the debug container runs as the
  # supervisor's own user, which satisfies the pod's runAsNonRoot and its
  # /proc/1 ownership. Without one (for example an OpenShift SCC assigns a
  # per-namespace range), pinning a guess would fail admission; the container
  # then omits runAsUser and lets the cluster decide, relying on the added
  # CAP_SYS_PTRACE (not a shared UID) for /proc/1 access.
  run_as_non_root="${run_as_non_root:-false}"
  if [[ -n "${run_as_user}" ]]; then
    run_as_user_line="  runAsUser: ${run_as_user}"
    run_as_non_root_line="  runAsNonRoot: ${run_as_non_root}"
  else
    run_as_user_line=""
    run_as_non_root_line=""
  fi
  custom_spec="$(mktemp "${results_dir}/openshell-census-debug.XXXXXX.yaml")"
  cat >"${custom_spec}" <<EOF
securityContext:
${run_as_user_line}
${run_as_non_root_line}
  allowPrivilegeEscalation: false
  capabilities:
    add: ["SYS_PTRACE"]
    drop: ["ALL"]
EOF

  echo "Waiting ${settle_seconds}s for ${created} sandboxes to settle on ${pod}..."
  sleep "${settle_seconds}"

  samples='[]'
  previous_threads=''
  settled=false
  stable=0
  for ((attempt = 1; attempt <= max_samples; attempt += 1)); do
    echo "Census sample ${attempt}/${max_samples}..."
    raw="$(census_sample "${context}" "${namespace}" "${pod}" "${debug_image}" "${custom_spec}")"
    if [[ -z "${raw}" ]]; then
      echo "ERROR: census returned no data; does the debug image have a shell?" >&2
      exit 1
    fi
    sample_json="$(census_to_json <<<"${raw}")"
    samples="$(jq -c --argjson sample "${sample_json}" '. + [$sample]' <<<"${samples}")"
    threads="$(jq -cS '.thread_names | keys' <<<"${sample_json}")"
    skipped="$(jq -r '.skipped_threads // 0' <<<"${sample_json}")"
    # Same rule as the rig's settled_threads: two consecutive identical thread
    # sets with no tid lost to churn between them count as settled, so a
    # replaced thread (one exits after its read, another spawns) still counts
    # as movement even when the count is unchanged.
    if [[ -n "${previous_threads}" && "${threads}" == "${previous_threads}" && "${skipped}" == "0" ]]; then
      stable=$((stable + 1))
      if [[ "${stable}" -ge 2 ]]; then
        settled=true
        break
      fi
    else
      stable=0
    fi
    previous_threads="${threads}"
    if [[ "${attempt}" -lt "${max_samples}" ]]; then
      sleep "${sample_interval}"
    fi
  done
  rm -f "${custom_spec}"

  result_file="${results_dir}/census-$(date -u +%Y%m%dT%H%M%SZ)-n${count}.json"
  jq -n \
    --argjson schema_version 1 \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg cluster "${OPENSHELL_CENSUS_CLUSTER:-}" \
    --arg context "${context}" \
    --arg namespace "${namespace}" \
    --arg supervisor_pod "${pod}" \
    --arg node "${node}" \
    --arg node_cpu_capacity "${node_cpu}" \
    --argjson requested_sandboxes "${count}" \
    --argjson created_sandboxes "${created}" \
    --argjson settle_seconds "${settle_seconds}" \
    --argjson sample_interval_seconds "${sample_interval}" \
    --arg debug_image "${debug_image}" \
    --arg overlay "${overlay}" \
    --argjson settled "${settled}" \
    --argjson samples "${samples}" \
    '{
      schema_version: $schema_version,
      generated_at: $generated_at,
      cluster: $cluster,
      context: $context,
      namespace: $namespace,
      supervisor_pod: $supervisor_pod,
      node: $node,
      node_cpu_capacity: $node_cpu_capacity,
      requested_sandboxes: $requested_sandboxes,
      created_sandboxes: $created_sandboxes,
      settle_seconds: $settle_seconds,
      sample_interval_seconds: $sample_interval_seconds,
      debug_image: $debug_image,
      overlay: $overlay,
      settled: $settled,
      samples: $samples
    }' >"${result_file}"

  echo "Wrote ${result_file}"
  jq -r '"N=\(.created_sandboxes) threads=\(.samples[-1].thread_count) fds=\(.samples[-1].fd_count) sockets=\(.samples[-1].socket_count) vm_rss_kib=\(.samples[-1].vm_rss_kib) settled=\(.settled) node_cpu=\(.node_cpu_capacity)"' \
    "${result_file}"
}

run_outer() {
  local count="$1" keep_cluster="$2"
  local results_dir="${OPENSHELL_CENSUS_RESULTS_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/openshell/census}"
  local existing_values="${OPENSHELL_E2E_KUBE_EXTRA_VALUES:-}"

  require_cmd jq
  require_cmd helm
  require_cmd kubectl
  if [[ -z "${OPENSHELL_BIN:-}" ]]; then
    require_cmd cargo
    echo "Building openshell CLI..."
    cargo build -p openshell-cli
    export OPENSHELL_BIN="${ROOT}/target/debug/openshell"
  fi

  CLUSTER_KEPT="${keep_cluster}"
  if [[ -n "${OPENSHELL_E2E_KUBE_CONTEXT:-}" ]]; then
    echo "Using existing kubectl context ${OPENSHELL_E2E_KUBE_CONTEXT}"
  else
    require_cmd "${KIND_BIN}"
    export KIND_EXPERIMENTAL_PROVIDER="${KIND_EXPERIMENTAL_PROVIDER:-podman}"
    require_cmd "${KIND_EXPERIMENTAL_PROVIDER}"

    # Rootless Podman needs delegated cgroups for the kind node containers.
    KIND_LAUNCHER=()
    if [[ "${KIND_EXPERIMENTAL_PROVIDER}" == "podman" ]] \
       && command -v systemd-run >/dev/null 2>&1 \
       && systemctl --user show-environment >/dev/null 2>&1; then
      KIND_LAUNCHER=(systemd-run --user --scope -p Delegate=yes --)
    fi

    CLUSTER_NAME="${OPENSHELL_CENSUS_CLUSTER:-openshell-census}"
    mkdir -p "${HOME}/.kube"
    local kubeconfig="${HOME}/.kube/kind-${CLUSTER_NAME}.yaml"
    local kind_config=""
    if "${KIND_BIN}" get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
      # The kubelet config below applies only when this script creates the
      # cluster; an existing cluster keeps the maxPods it was created with.
      echo "Reusing kind cluster ${CLUSTER_NAME}"
      "${KIND_BIN}" export kubeconfig --name "${CLUSTER_NAME}" --kubeconfig "${kubeconfig}"
    else
      echo "Creating kind cluster ${CLUSTER_NAME} (provider=${KIND_EXPERIMENTAL_PROVIDER})"
      # kind's defaults cap a single node below the 256 sandboxes the scale
      # overlay sizes for: kubelet maxPods is 110 and the node's pod CIDR is a
      # /24 (~250 addresses), so raise both. The controller-manager setting
      # must patch the ClusterConfiguration document: kind drops a kubeadm
      # patch that matches no document in the config it generates.
      kind_config="$(mktemp "${TMPDIR:-/tmp}/openshell-census-kind.XXXXXX.yaml")"
      cat >"${kind_config}" <<'KIND'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
  - |
    kind: KubeletConfiguration
    maxPods: 512
  - |
    kind: ClusterConfiguration
    controllerManager:
      extraArgs:
        node-cidr-mask-size: "23"
KIND
      "${KIND_LAUNCHER[@]+"${KIND_LAUNCHER[@]}"}" "${KIND_BIN}" create cluster \
        --name "${CLUSTER_NAME}" --kubeconfig "${kubeconfig}" \
        --config "${kind_config}" --wait 120s
      rm -f "${kind_config}"
      CLUSTER_CREATED=1
    fi
    export KUBECONFIG="${kubeconfig}"
    export OPENSHELL_E2E_KUBE_CONTEXT="kind-${CLUSTER_NAME}"
  fi

  # The overlay keeps gateway TLS on, so the wrapper must register an mTLS
  # gateway and use its TCP-only port-forward health check instead of
  # plaintext curls against the TLS listener.
  export OPENSHELL_E2E_KUBE_TLS=1
  # run_census creates this too, but it runs only in the --inner invocation,
  # after the image archives below have already been written here.
  mkdir -p "${results_dir}"
  local build_images="${OPENSHELL_E2E_KUBE_BUILD_IMAGES:-1}"
  if [[ "${build_images}" == "1" && -n "${CLUSTER_NAME:-}" \
        && "${KIND_EXPERIMENTAL_PROVIDER:-podman}" == "podman" ]]; then
    # The e2e wrapper's image building requires a Docker CLI and hardcodes
    # CONTAINER_ENGINE=docker, which a Podman-only host cannot satisfy. With
    # the Podman provider, build and load the images here, then let the
    # wrapper deploy the already-loaded set. The images the census measures
    # are the ones built from this checkout, so the wrapper's image override
    # variables must not be set to something the script never loaded.
    if [[ -n "${GATEWAY_IMAGE:-}" || -n "${SUPERVISOR_IMAGE:-}" || -n "${SANDBOX_IMAGE:-}" ]]; then
      echo "ERROR: GATEWAY_IMAGE, SUPERVISOR_IMAGE, and SANDBOX_IMAGE must be unset when the script builds its own images; unset them, or set OPENSHELL_E2E_KUBE_BUILD_IMAGES=0 and load the images yourself" >&2
      exit 1
    fi
    local tag component
    tag="census-$(git -C "${ROOT}" rev-parse --short HEAD)"
    for component in gateway supervisor sandbox; do
      CONTAINER_ENGINE=podman IMAGE_REGISTRY=localhost/openshell IMAGE_TAG="${tag}" \
        bash "${ROOT}/tasks/scripts/docker-build-image.sh" "${component}"
      podman save -o "${results_dir}/${component}.tar" \
        "localhost/openshell/${component}:${tag}"
      "${KIND_BIN}" load image-archive "${results_dir}/${component}.tar" \
        --name "${CLUSTER_NAME}"
      rm -f "${results_dir}/${component}.tar"
    done
    export OPENSHELL_REGISTRY=localhost/openshell
    export IMAGE_TAG="${tag}"
    build_images=0
  fi
  export OPENSHELL_E2E_KUBE_BUILD_IMAGES="${build_images}"
  export OPENSHELL_E2E_KUBE_EXTRA_VALUES
  OPENSHELL_E2E_KUBE_EXTRA_VALUES="$(census_overlay)${existing_values:+:${existing_values}}"

  export OPENSHELL_CENSUS_SANDBOXES="${count}"
  export OPENSHELL_CENSUS_CLUSTER="${CLUSTER_NAME:-${OPENSHELL_CENSUS_CLUSTER:-}}"
  export OPENSHELL_CENSUS_RESULTS_DIR="${results_dir}"

  echo "Deploying the chart with overlay:"
  echo "  ${OPENSHELL_E2E_KUBE_EXTRA_VALUES}"

  # The e2e wrapper finds `kind` with `command -v kind` and honors no env
  # override for it, so a KIND_BIN whose basename is not `kind` (for example a
  # downloaded kind-linux-amd64) must appear on PATH under that name or the
  # wrapper silently skips loading locally built images. A relative KIND_BIN
  # would dangle once the cwd changes, so resolve it first.
  local kind_bin_abs
  kind_bin_abs="$(command -v "${KIND_BIN}" 2>/dev/null || echo "${KIND_BIN}")"
  case "${kind_bin_abs}" in
    /*) ;;
    *) kind_bin_abs="$(cd "$(dirname "${kind_bin_abs}")" && pwd)/$(basename "${kind_bin_abs}")" ;;
  esac
  KIND_ON_PATH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-census-kind-bin.XXXXXX")"
  ln -s "${kind_bin_abs}" "${KIND_ON_PATH_DIR}/kind"
  export PATH="${KIND_ON_PATH_DIR}:${PATH}"

  "${ROOT}/e2e/with-kube-gateway.sh" bash "${SCRIPT_PATH}" --inner
}

main() {
  local count="${OPENSHELL_CENSUS_SANDBOXES:-8}"
  local keep_cluster="${OPENSHELL_CENSUS_KEEP_CLUSTER:-0}"
  local inner=0

  while (($# > 0)); do
    case "$1" in
      --inner)
        inner=1
        ;;
      --sandboxes)
        count="${2:?--sandboxes requires a value}"
        shift
        ;;
      --sandboxes=*)
        count="${1#*=}"
        ;;
      --keep-cluster)
        keep_cluster=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "ERROR: unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done

  if ! [[ "${count}" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: sandbox count must be a positive integer, got: ${count}" >&2
    exit 2
  fi

  # A zero-sample census would write an empty result file and exit zero.
  if ! [[ "${OPENSHELL_CENSUS_MAX_SAMPLES:-6}" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: OPENSHELL_CENSUS_MAX_SAMPLES must be a positive integer, got: ${OPENSHELL_CENSUS_MAX_SAMPLES}" >&2
    exit 2
  fi

  if ((count > MAX_SANDBOXES)); then
    echo "ERROR: sandbox count ${count} exceeds the ${MAX_SANDBOXES} sandboxes the scale overlay sizes the supervisor pool for (supervisor.pool.maxInstancesPerMember); lower --sandboxes" >&2
    exit 2
  fi

  if [[ "${inner}" == "1" ]]; then
    run_census
    return
  fi

  trap cleanup_cluster EXIT
  run_outer "${count}" "${keep_cluster}"
}

main "$@"
