#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

base=$(git merge-base "$1" "$2")
head=$2

# Treat a move into the frozen tree like any other new file.
new_files=$(git diff --no-renames --name-only --diff-filter=A "$base" "$head" -- e2e/rust/tests/)

# Scan added lines only; hunk headers and context must not count. Match
# parameterized Tokio attributes too, including when their arguments wrap.
new_attributes=$(git diff --no-renames --no-ext-diff --no-textconv --no-color --no-prefix --text \
  --unified=0 "$base" "$head" -- e2e/rust/ |
  awk '
    /^diff --git / { path = ""; in_hunk = 0 }
    /^\+\+\+ / && !in_hunk { path = substr($0, 5) }
    /^@@ / { in_hunk = 1 }
    in_hunk && /^\+[[:space:]]*#[[:space:]]*\[[[:space:]]*(test[[:space:]]*\]|tokio[[:space:]]*::[[:space:]]*test[[:space:]]*(\]|\())/ {
      print "  " path ": " substr($0, 2)
    }
  ')

if [[ -z "$new_files" && -z "$new_attributes" ]]; then
  exit 0
fi

echo "::error title=Rust E2E Freeze::e2e/rust is frozen to new tests. See TESTING.md: Where a new test goes." >&2
if [[ -n "$new_files" ]]; then
  echo "New files under e2e/rust/tests:" >&2
  printf '  %s\n' "${new_files//$'\n'/$'\n  '}" >&2
fi
if [[ -n "$new_attributes" ]]; then
  echo "New test attributes under e2e/rust:" >&2
  echo "$new_attributes" >&2
fi
exit 1
