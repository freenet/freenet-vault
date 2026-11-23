//! Coverage counters (15.5): every row of 5.1, 6 and 7.6, every CompleteAck
//! status and every fault type must be hit at least once per gate run.

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct Cov {
    pub counts: BTreeMap<String, u64>,
}

impl Cov {
    pub fn hit(&mut self, k: &str) {
        *self.counts.entry(k.to_string()).or_insert(0) += 1;
    }
    pub fn get(&self, k: &str) -> u64 {
        self.counts.get(k).copied().unwrap_or(0)
    }
    pub fn merge(&mut self, o: &Cov) {
        for (k, v) in &o.counts {
            *self.counts.entry(k.clone()).or_insert(0) += v;
        }
    }
    /// Required counters that are still zero.
    pub fn missing(&self) -> Vec<&'static str> {
        REQUIRED
            .iter()
            .copied()
            .filter(|k| self.get(k) == 0)
            .collect()
    }
}

/// The counters a gate run must hit. Rows the model cannot reach by
/// construction are listed in `UNREACHABLE` with the reason.
pub const REQUIRED: &[&str] = &[
    // 5.1: state x access
    "5.1/NONE/read",
    "5.1/NONE/change",
    "5.1/NONE/mark",
    "5.1/created",
    "5.1/WRITER/read",
    "5.1/WRITER/change",
    "5.1/WRITER/mark",
    "5.1/WRITER(awaiting)/read",
    "5.1/WRITER(awaiting)/change",
    "5.1/WRITER(awaiting)/mark",
    "5.1/SEALED/read",
    "5.1/SEALED/change",
    "5.1/SEALED/mark",
    "5.1/RECEIVING/read",
    "5.1/RECEIVING/change",
    "5.1/RETIRED/read",
    "5.1/RETIRED/change",
    "5.1/RETIRED/mark",
    "5.1/arming-cleared-by-record",
    // 6: trigger rule rows
    "6/poke",
    "6/wakeup",
    "6/ack-from-successor",
    "6/receiver-role",
    "6/predecessor-role",
    "6/ignored",
    // 7.6 receiver rows x frame
    "7.6/taken-over-from-P/Chunk",
    "7.6/taken-over-from-P/Complete",
    "7.6/taken-over-from-P/Abort",
    "7.6/taken-over-from-P/Retired",
    "7.6/other-writer-or-not-from-P/Chunk",
    "7.6/other-writer-or-not-from-P/Complete",
    "7.6/other-writer-or-not-from-P/Abort",
    "7.6/other-writer-or-not-from-P/Retired",
    "7.6/stopped/Chunk",
    "7.6/stopped/Complete",
    "7.6/stopped/Abort",
    "7.6/NONE/Chunk",
    "7.6/NONE/Complete",
    "7.6/NONE/Abort",
    "7.6/RECEIVING(P)/Chunk",
    "7.6/RECEIVING(P)/Complete",
    "7.6/RECEIVING(P)/Abort",
    "7.6/RECEIVING(lower)/Chunk",
    "7.6/RECEIVING(lower)/Complete",
    "7.6/RECEIVING(higher)/Chunk",
    "7.6/RECEIVING(higher)/Complete",
    "7.6/malformed/Chunk",
    "7.6/malformed/Complete",
    // 7.6 Query table
    "7.6q/RETIRED",
    "7.6q/NONE",
    "7.6q/SEALED-toward-querier-same-m",
    "7.6q/anything-else",
    // CompleteAck statuses received by a sealed sender
    "7.5/completeack/Accepted",
    "7.5/completeack/Missing",
    "7.5/completeack/AlreadyWriter",
    "7.5/completeack/Stopped",
    "7.5/completeack/HigherBuild",
    "7.5/completeack/StorageFailure",
    "7.5/completeack/Aborted",
    "7.5/completeack/AnotherWriter",
    "7.5/completeack/DifferentManifest",
    "7.5/completeack/Malformed",
    // CompleteAck statuses sent (Noted answers Retired and Query)
    "sent/CompleteAck/Accepted",
    "sent/CompleteAck/Missing",
    "sent/CompleteAck/AlreadyWriter",
    "sent/CompleteAck/Stopped",
    "sent/CompleteAck/HigherBuild",
    "sent/CompleteAck/StorageFailure",
    "sent/CompleteAck/Aborted",
    "sent/CompleteAck/AnotherWriter",
    "sent/CompleteAck/DifferentManifest",
    "sent/CompleteAck/Malformed",
    "sent/CompleteAck/Noted",
    // Ack statuses and outcomes
    "7.3/ack/Processed",
    "7.3/ack/Stopped",
    "7.3/ack/AnotherWriter",
    "7.2/outcome-stored",
    "7.2/outcome-identical",
    "7.2/outcome-policy-dropped",
    "7.2/outcome-staging-full",
    "7.2/outcome-storage-failure",
    // key transitions
    "7.4/sealed",
    "7.4/took-over",
    "7.4/retired",
    "7.4/awaiting-cleared-by-retired",
    "7.4/unlisted-dropped",
    "7.5/unsealed",
    "7.5/step-abort",
    "4.2/gc-processed",
    "4.3/corrupt-rewritten-flagged",
    "4.3/corrupt-unparseable-removed",
    "13.1/armed",
    // faults (15.3)
    "fault/hop-lost",
    "fault/reply-lost",
    "fault/crash-between-calls",
    "fault/crash-before-write",
    "fault/crash-after-write",
    "fault/storage-failure",
    "fault/durable-but-error",
    "fault/quota",
    "fault/unregister",
    "fault/restore-whole",
    "fault/restore-secret",
    "fault/wipe",
    "fault/garble-secret",
    "fault/pointer-unreachable",
    "fault/hop-cap",
    "fault/garbled-hop",
    "publish/withdrawal",
    "publish/rollback",
    "client/old-lineage",
    "client/cached-caller",
];
