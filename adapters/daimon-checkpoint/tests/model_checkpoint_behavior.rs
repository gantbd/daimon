use daimon_checkpoint::model::{CheckpointModelExecutionStore, ModelStoreLimitsV1, decode, encode};
use daimon_host::{
    ModelExecutionStore, ModelServiceSnapshotV1, StoreCommitV1, StoredModelExecutionStateV1,
    StoredModelExecutionV1,
};
use daimon_protocol as protocol;
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::convert::Infallible;

fn limits() -> ModelStoreLimitsV1 {
    ModelStoreLimitsV1 {
        max_bytes: 64 * 1024,
        max_executions: 4,
        max_context_references: 4,
        max_tools: 4,
        max_model_bytes: 128,
        max_context_bytes: 4 * 1024,
        max_messages: 8,
        max_message_bytes: 4 * 1024,
        max_output_bytes: 4 * 1024,
        max_proposals: 4,
        max_proposal_bytes: 4 * 1024,
    }
}

fn stored(id: u8, completed: bool) -> StoredModelExecutionV1 {
    let execution_id = protocol::ExecutionIdV1::new([id; 16]);
    let profile = protocol::HarnessProfileIdV1::new([5; 16]);
    let reference = protocol::ContextReferenceIdV1::new([id + 20; 16]);
    let request = protocol::ExecuteRequestV1 {
        execution_id,
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 3,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([4; 16]),
        profile,
        idempotency_key: protocol::IdempotencyKeyV1::new([id + 10; 16]),
        context: vec![reference],
        tools: vec![protocol::ToolCapabilityIdV1::new([41; 16])],
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 1,
            max_context_bytes: 1_024,
            max_output_bytes: 1_024,
        },
    };
    let invocation = protocol::ModelInvocationV1 {
        execution_id,
        provider: protocol::ProviderProfileSnapshotV1 {
            provider: protocol::ProviderProfileIdV1::new([30; 16]),
            harness_profile: profile,
            wire: protocol::ProviderWireProfileV1::OpenAiChatCompletions,
            model: b"local-model".to_vec(),
            structured_tools: true,
            document_digest: protocol::ContentDigestV1::new([31; 32]),
        },
        context: vec![protocol::ContextEvidenceV1 {
            reference,
            kind: protocol::ContextKindV1::DendriteGrounding,
            bytes: b"verified surface".to_vec(),
            source_digest: protocol::ContentDigestV1::new([32; 32]),
            grounding: Some(protocol::GroundingEvidenceV1 {
                depth: protocol::GroundingDepthV1::Activated,
                grounding_digest: protocol::ContentDigestV1::new([33; 32]),
                surface_digest: protocol::ContentDigestV1::new([34; 32]),
            }),
        }],
        tools: vec![protocol::ToolCapabilityIdV1::new([41; 16])],
        continuation: Some(protocol::ModelContinuationV1 {
            source_execution: protocol::ExecutionIdV1::new([99; 16]),
            source_output: Vec::new(),
            results: vec![protocol::ModelToolResultV1 {
                request: [42; 16],
                capability: protocol::ToolCapabilityIdV1::new([41; 16]),
                provider_correlation: b"call-42".to_vec(),
                arguments: br#"{"path":"README.md"}"#.to_vec(),
                evidence_digest: protocol::ContentDigestV1::new([43; 32]),
                output_digest: protocol::ContentDigestV1::new([44; 32]),
                output: b"contents".to_vec(),
            }],
        }),
        messages: vec![protocol::ModelMessageV1 {
            role: protocol::MessageRoleV1::User,
            content: b"question".to_vec(),
        }],
        estimated_input_tokens: 4,
    };
    let state = if completed {
        StoredModelExecutionStateV1::Completed(protocol::ModelExecutionResultV1 {
            execution_id,
            disposition: protocol::ExecutionDispositionV1::Completed,
            evidence_digest: protocol::ContentDigestV1::new([35; 32]),
            input_tokens: 4,
            output_tokens: 5,
            output: b"answer".to_vec(),
            proposals: vec![
                protocol::OutputProposalV1::AgoraMessage(protocol::AgoraMessageProposalV1 {
                    room: [36; 16],
                    reply_to: [37; 16],
                    body: b"answer".to_vec(),
                }),
                protocol::OutputProposalV1::VellumEdit(protocol::VellumEditProposalV1 {
                    workspace: [38; 16],
                    document: [39; 16],
                    expected_revision: 6,
                    replacement: b"reviewed edit".to_vec(),
                }),
                protocol::OutputProposalV1::ToolCall(protocol::ToolCallProposalV1 {
                    request: [42; 16],
                    capability: protocol::ToolCapabilityIdV1::new([41; 16]),
                    provider_correlation: b"call-42".to_vec(),
                    arguments: br#"{"path":"README.md"}"#.to_vec(),
                }),
            ],
        })
    } else {
        StoredModelExecutionStateV1::OutcomeUnknown
    };
    StoredModelExecutionV1 {
        request,
        authority_decision: [40; 16],
        authority_expires_at: 100,
        authority_tools: vec![protocol::ToolCapabilityIdV1::new([41; 16])],
        prepared_at: 10,
        invocation,
        state,
    }
}

fn snapshot() -> ModelServiceSnapshotV1 {
    ModelServiceSnapshotV1 {
        executions: vec![stored(1, false), stored(2, true)],
    }
}

#[test]
fn exact_invocation_grounding_and_typed_result_roundtrip_canonically() {
    let snapshot = snapshot();
    let bytes = encode(&snapshot, limits()).unwrap();
    assert_eq!(decode(&bytes, limits()).unwrap(), snapshot);
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end], limits()).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode(&trailing, limits()).is_err());
}

#[test]
fn checkpoint_rejects_profile_context_and_result_identity_drift() {
    let mut profile = snapshot();
    profile.executions[0].invocation.provider.harness_profile =
        protocol::HarnessProfileIdV1::new([99; 16]);
    assert!(encode(&profile, limits()).is_err());

    let mut context = snapshot();
    context.executions[0].invocation.context[0].reference =
        protocol::ContextReferenceIdV1::new([99; 16]);
    assert!(encode(&context, limits()).is_err());

    let mut result_snapshot = snapshot();
    let StoredModelExecutionStateV1::Completed(result) = &mut result_snapshot.executions[1].state
    else {
        unreachable!()
    };
    result.execution_id = protocol::ExecutionIdV1::new([99; 16]);
    assert!(encode(&result_snapshot, limits()).is_err());
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
            mechanism: "daimon-model-checkpoint-test",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

#[test]
fn durable_model_store_reopens_the_exact_snapshot() {
    let mut store = CheckpointModelExecutionStore::create(Store::default(), limits()).unwrap();
    assert_eq!(
        store.load_model().unwrap(),
        Some(ModelServiceSnapshotV1::default())
    );
    assert_eq!(
        store.commit_model(&snapshot()).unwrap(),
        StoreCommitV1::Committed
    );
    let backend = store.into_inner();
    let mut reopened = CheckpointModelExecutionStore::open_existing(backend, limits()).unwrap();
    assert_eq!(reopened.load_model().unwrap(), Some(snapshot()));
}
