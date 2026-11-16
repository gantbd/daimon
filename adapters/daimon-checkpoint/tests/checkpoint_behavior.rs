use daimon_checkpoint::{CheckpointExecutionStore, StoreLimitsV1, decode, encode};
use daimon_host::{
    ExecutionStore, ServiceSnapshotV1, StoreCommitV1, StoredExecutionStateV1, StoredExecutionV1,
};
use daimon_protocol::{
    ArtifactReferenceIdV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionDispositionV1,
    ExecutionIdV1, ExecutionResultV1, HarnessProfileIdV1, IdempotencyKeyV1, PrincipalIdV1,
    TaskAttemptRefV1, ToolCapabilityIdV1,
};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::convert::Infallible;

fn limits() -> StoreLimitsV1 {
    StoreLimitsV1 {
        max_bytes: 8_192,
        max_executions: 4,
        max_context_references: 4,
        max_tools: 4,
        max_artifacts: 4,
    }
}

fn stored(id: u8, state: StoredExecutionStateV1) -> StoredExecutionV1 {
    StoredExecutionV1 {
        request: ExecuteRequestV1 {
            execution_id: ExecutionIdV1::new([id; 16]),
            task_attempt: TaskAttemptRefV1 {
                task_key: [2; 16],
                task_incarnation: 3,
                attempt_number: 1,
            },
            principal: PrincipalIdV1::new([4; 16]),
            profile: HarnessProfileIdV1::new([5; 16]),
            idempotency_key: IdempotencyKeyV1::new([id + 10; 16]),
            context: vec![],
            tools: vec![ToolCapabilityIdV1::new([6; 16])],
            budget: ExecutionBudgetV1 {
                max_elapsed_millis: 1_000,
                max_input_tokens: 100,
                max_output_tokens: 100,
                max_tool_calls: 1,
                max_context_bytes: 1_024,
                max_output_bytes: 1_024,
            },
        },
        authority_decision: [8; 16],
        authority_expires_at: 20,
        authority_tools: vec![ToolCapabilityIdV1::new([6; 16])],
        prepared_at: 10,
        state,
    }
}

fn snapshot() -> ServiceSnapshotV1 {
    ServiceSnapshotV1 {
        executions: vec![
            stored(1, StoredExecutionStateV1::OutcomeUnknown),
            stored(
                2,
                StoredExecutionStateV1::Completed(ExecutionResultV1 {
                    execution_id: ExecutionIdV1::new([2; 16]),
                    disposition: ExecutionDispositionV1::Completed,
                    produced_artifacts: vec![ArtifactReferenceIdV1::new([9; 16])],
                    output_bytes: 12,
                }),
            ),
        ],
    }
}

#[test]
fn canonical_snapshot_roundtrips_and_rejects_every_truncation_or_trailing_byte() {
    let snapshot = snapshot();
    let bytes = encode(&snapshot, limits()).unwrap();
    assert_eq!(decode(&bytes, limits()).unwrap(), snapshot);
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end], limits()).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode(&trailing, limits()).is_err());
}

#[test]
fn execution_order_and_result_identity_are_canonical() {
    let mut unsorted = snapshot();
    unsorted.executions.swap(0, 1);
    assert!(encode(&unsorted, limits()).is_err());
    let mut mismatched = snapshot();
    let StoredExecutionStateV1::Completed(result) = &mut mismatched.executions[1].state else {
        unreachable!()
    };
    result.execution_id = ExecutionIdV1::new([3; 16]);
    assert!(encode(&mismatched, limits()).is_err());
}

#[derive(Default)]
struct Store(Option<Checkpoint>);

impl CheckpointStore for Store {
    type Error = Infallible;

    fn load(&self, _: &str) -> Result<Option<Checkpoint>, Self::Error> {
        Ok(self.0.clone())
    }

    fn compare_exchange(
        &mut self,
        _: &str,
        expected: Option<Revision>,
        bytes: &[u8],
    ) -> Result<CommitOutcome, Self::Error> {
        let actual = self.0.as_ref().map(|checkpoint| checkpoint.revision);
        if actual != expected {
            return Ok(CommitOutcome::Refused(StoreRefusal::RevisionConflict {
                expected,
                actual,
            }));
        }
        let revision = Revision(actual.map_or(0, |value| value.0 + 1));
        self.0 = Some(Checkpoint {
            revision,
            bytes: bytes.to_vec(),
            strength: AcknowledgementStrength::Durable,
        });
        Ok(CommitOutcome::Committed(CommitReceipt {
            revision,
            mechanism: "daimon-checkpoint-test",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

#[test]
fn exact_checkpoint_revision_reopens_without_adopting_missing_state() {
    let mut store = CheckpointExecutionStore::create(Store::default(), limits()).unwrap();
    assert_eq!(store.load().unwrap(), Some(ServiceSnapshotV1::default()));
    assert_eq!(store.commit(&snapshot()).unwrap(), StoreCommitV1::Committed);
    let backend = store.into_inner();
    let mut reopened = CheckpointExecutionStore::open_existing(backend, limits()).unwrap();
    assert_eq!(reopened.load().unwrap(), Some(snapshot()));

    let mut missing = CheckpointExecutionStore::open_existing(Store::default(), limits()).unwrap();
    assert!(missing.load().is_err());
}
