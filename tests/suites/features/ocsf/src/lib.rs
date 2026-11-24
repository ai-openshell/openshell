// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reads the OCSF JSON records a supervisor writes to its stderr.

use testkit::ResultExt as _;

/// The marker before each JSON record on the supervisor's stderr.
pub const JSON_MARKER: &str = " OCSF-JSON ";

/// The JSON records in `stderr`, one per ` OCSF-JSON ` line. Each must be a
/// whole JSON object with no terminal escapes.
pub fn json_records(stderr: &str) -> testkit::Result<Vec<serde_json::Value>> {
    stderr
        .lines()
        .filter_map(|line| line.split_once(JSON_MARKER).map(|(_, payload)| payload))
        .map(|payload| {
            testkit::ensure!(
                !payload.contains('\x1b'),
                "an OCSF JSON line has terminal escapes: {payload:?}"
            );
            serde_json::from_str(payload).context(format!("parse OCSF JSON line {payload:?}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_records_reads_marked_lines_only() {
        let stderr = "2026 INFO OCSF NET:OPEN [MED] DENIED\n\
                      2026 INFO OCSF-JSON {\"class_uid\":4001}\n";
        let records = json_records(stderr).unwrap();
        assert_eq!(records, vec![serde_json::json!({"class_uid": 4001})]);
    }

    #[test]
    fn json_records_rejects_escapes() {
        assert!(json_records("x OCSF-JSON \x1b[1m{}\n").is_err());
    }
}
