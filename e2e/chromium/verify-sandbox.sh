#!/bin/sh
set -eu

baseline_ns=$(readlink /proc/self/ns/user)
baseline_filters=$(awk '/^Seccomp_filters:/ {print $2}' /proc/self/status)

chromium \
  --headless \
  --disable-gpu \
  --disable-dev-shm-usage \
  --no-first-run \
  --user-data-dir=/tmp/chromium-e2e-profile \
  about:blank >/tmp/chromium-e2e.log 2>&1 &

browser_pid=$!
trap 'kill "$browser_pid" 2>/dev/null || true' EXIT

sleep 5

verified=0

for proc in /proc/[0-9]*; do
  executable=$(readlink "$proc/exe" 2>/dev/null || true)

  case "$executable" in
    */chromium|*/chrome) ;;
    *) continue ;;
  esac

  args=$(tr '\000' ' ' < "$proc/cmdline" 2>/dev/null || true)

  case "$args" in
    *--type=renderer*) ;;
    *) continue ;;
  esac

  namespace=$(readlink "$proc/ns/user" 2>/dev/null || true)
  nnp=$(awk '/^NoNewPrivs:/ {print $2}' "$proc/status" 2>/dev/null || true)
  seccomp=$(awk '/^Seccomp:/ {print $2}' "$proc/status" 2>/dev/null || true)
  filters=$(awk '/^Seccomp_filters:/ {print $2}' "$proc/status" 2>/dev/null || true)
  capabilities=$(awk '/^CapEff:/ {print $2}' "$proc/status" 2>/dev/null || true)

  if [ "$namespace" != "$baseline_ns" ] &&
     [ -n "$namespace" ] &&
     [ "$nnp" = 1 ] &&
     [ "$seccomp" = 2 ] &&
     [ "$capabilities" = 0000000000000000 ] &&
     [ -n "$filters" ] &&
     [ "$filters" -gt "$baseline_filters" ]; then
    verified=$((verified + 1))
  fi
done

if [ "$verified" -lt 1 ]; then
  echo "CHROMIUM_SANDBOX_VERIFICATION_FAILED"
  tail -n 30 /tmp/chromium-e2e.log
  exit 1
fi

echo "CHROMIUM_SANDBOX_VERIFIED renderers=$verified"
