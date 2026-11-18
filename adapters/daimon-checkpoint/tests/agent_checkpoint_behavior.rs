use daimon_checkpoint::agent::{AgentStoreLimitsV1, CheckpointAgentSessionStore, decode, encode};
use daimon_host::{
    StoreCommitV1,
    agent::{
        AgentServiceSnapshotV1, AgentSessionStore, StoredAgentOperationInputV1,
        StoredAgentOperationStateV1, StoredAgentOperationV1, StoredAgentPreparationV1,
        StoredAgentSessionV1,
    },
};
use daimon_protocol::{self as protocol, agent::*};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::convert::Infallible;

fn limits() -> AgentStoreLimitsV1 {
    AgentStoreLimitsV1 {
        max_bytes: 64 * 1024,
        max_sessions: 4,
        max_operations_per_session: 8,
        max_events_per_session: 16,
        max_context_references: 4,
        max_tools: 4,
        max_prompt_bytes: 4 * 1024,
        max_event_bytes: 4 * 1024,
        max_permission_options: 4,
    }
}

fn execution(seed: u8, idempotency: u8) -> protocol::ExecuteRequestV1 {
    protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([seed; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 3,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([4; 16]),
        profile: protocol::HarnessProfileIdV1::new([5; 16]),
        idempotency_key: protocol::IdempotencyKeyV1::new([idempotency; 16]),
        context: vec![protocol::ContextReferenceIdV1::new([6; 16])],
        tools: vec![protocol::ToolCapabilityIdV1::new([7; 16])],
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 2,
            max_context_bytes: 1_024,
            max_output_bytes: 1_024,
        },
    }
}

fn preparation(seed: u8) -> StoredAgentPreparationV1 {
    StoredAgentPreparationV1 {
        authority_decision: [seed; 16],
        authority_expires_at: 100,
        authority_tools: vec![protocol::ToolCapabilityIdV1::new([7; 16])],
        prepared_at: 10,
    }
}

fn view(revision: u64, phase: AgentSessionPhaseV1) -> AgentSessionViewV1 {
    AgentSessionViewV1 {
        session: protocol::AgentSessionIdV1::new([8; 16]),
        revision,
        phase,
        profile_document_digest: protocol::ContentDigestV1::new([9; 32]),
        active_turn: None,
        last_event_cursor: Some(2),
        last_context: Some(context_receipt()),
        capabilities: AgentCapabilitiesV1 {
            permissions: true,
            terminal: true,
            ..AgentCapabilitiesV1::default()
        },
    }
}

fn context_receipt() -> AgentContextReceiptV1 {
    AgentContextReceiptV1 {
        execution: protocol::ExecutionIdV1::new([24; 16]),
        manifest_digest: protocol::ContentDigestV1::new([25; 32]),
        entries: vec![AgentContextManifestEntryV1 {
            reference: protocol::ContextReferenceIdV1::new([26; 16]),
            kind: protocol::ContextKindV1::VellumDocument,
            source_digest: protocol::ContentDigestV1::new([27; 32]),
            content_bytes: 4_096,
            grounding: None,
        }],
    }
}

fn snapshot() -> AgentServiceSnapshotV1 {
    let session = protocol::AgentSessionIdV1::new([8; 16]);
    let turn = protocol::AgentTurnIdV1::new([10; 16]);
    let prompt = b"inspect exact boundaries".to_vec();
    AgentServiceSnapshotV1 {
        sessions: vec![StoredAgentSessionV1 {
            request: AgentOpenRequestV1 {
                session,
                execution: execution(1, 7),
                workspace: [11; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 10_000,
                    max_turns: 4,
                    max_events: 16,
                    max_event_bytes: 4 * 1024,
                    max_prompt_bytes: 4 * 1024,
                    max_permission_requests: 4,
                },
            },
            open_preparation: preparation(12),
            profile: AgentProfileSnapshotV1 {
                provider: protocol::ProviderProfileIdV1::new([13; 16]),
                harness_profile: protocol::HarnessProfileIdV1::new([5; 16]),
                wire: AgentWireProfileV1::AgentClientProtocol,
                command_digest: protocol::ContentDigestV1::new([14; 32]),
                policy_digest: protocol::ContentDigestV1::new([15; 32]),
                document_digest: protocol::ContentDigestV1::new([9; 32]),
            },
            revision: 6,
            phase: AgentSessionPhaseV1::Closed,
            active_turn: None,
            capabilities: AgentCapabilitiesV1 {
                resume_session: true,
                permissions: true,
                terminal: true,
                ..AgentCapabilitiesV1::default()
            },
            recovery: Some(daimon_host::agent::AgentProviderRecoveryV1 {
                locator: b"opaque-provider-session".to_vec(),
            }),
            last_context: Some(context_receipt()),
            events: vec![
                AgentEventRecordV1 {
                    cursor: 0,
                    event: AgentEventV1::AssistantMessage {
                        bytes: b"working".to_vec(),
                    },
                },
                AgentEventRecordV1 {
                    cursor: 1,
                    event: AgentEventV1::Permission(AgentPermissionRequestV1 {
                        request: protocol::AgentPermissionRequestIdV1::new([16; 16]),
                        turn,
                        capability: b"terminal".to_vec(),
                        description: b"run tests".to_vec(),
                        options: vec![AgentPermissionOptionV1 {
                            id: protocol::AgentPermissionOptionIdV1::new([17; 16]),
                            kind: AgentPermissionOptionKindV1::AllowOnce,
                            label: b"allow once".to_vec(),
                        }],
                    }),
                },
                AgentEventRecordV1 {
                    cursor: 2,
                    event: AgentEventV1::FileRead {
                        path: b"Cargo.toml".to_vec(),
                        content_digest: protocol::ContentDigestV1::new([21; 32]),
                        content_bytes: 42,
                    },
                },
                AgentEventRecordV1 {
                    cursor: 3,
                    event: AgentEventV1::TurnFinished {
                        turn,
                        disposition: protocol::ExecutionDispositionV1::Cancelled,
                        stop_reason: AgentTurnStopReasonV1::Cancelled,
                        output_digest: None,
                    },
                },
            ],
            operations: vec![
                StoredAgentOperationV1 {
                    idempotency_key: protocol::IdempotencyKeyV1::new([11; 16]),
                    input: StoredAgentOperationInputV1::Prompt(AgentTurnRequestV1 {
                        session,
                        turn,
                        expected_revision: 1,
                        execution: execution(18, 11),
                        prompt_digest: protocol::ContentDigestV1::new([19; 32]),
                        prompt,
                    }),
                    preparation: Some(preparation(20)),
                    state: StoredAgentOperationStateV1::Completed(view(
                        2,
                        AgentSessionPhaseV1::AwaitingPermission,
                    )),
                },
                StoredAgentOperationV1 {
                    idempotency_key: protocol::IdempotencyKeyV1::new([21; 16]),
                    input: StoredAgentOperationInputV1::Permission {
                        expected_revision: 2,
                        execution: execution(22, 21),
                        decision: AgentPermissionDecisionV1 {
                            request: protocol::AgentPermissionRequestIdV1::new([16; 16]),
                            option: protocol::AgentPermissionOptionIdV1::new([17; 16]),
                        },
                    },
                    preparation: Some(preparation(23)),
                    state: StoredAgentOperationStateV1::Completed(view(
                        3,
                        AgentSessionPhaseV1::Ready,
                    )),
                },
                StoredAgentOperationV1 {
                    idempotency_key: protocol::IdempotencyKeyV1::new([22; 16]),
                    input: StoredAgentOperationInputV1::Advance {
                        turn,
                        expected_revision: 3,
                    },
                    preparation: None,
                    state: StoredAgentOperationStateV1::Completed(view(
                        4,
                        AgentSessionPhaseV1::TurnActive,
                    )),
                },
                StoredAgentOperationV1 {
                    idempotency_key: protocol::IdempotencyKeyV1::new([23; 16]),
                    input: StoredAgentOperationInputV1::Cancel {
                        turn,
                        expected_revision: 4,
                    },
                    preparation: None,
                    state: StoredAgentOperationStateV1::Completed(view(
                        5,
                        AgentSessionPhaseV1::Ready,
                    )),
                },
                StoredAgentOperationV1 {
                    idempotency_key: protocol::IdempotencyKeyV1::new([24; 16]),
                    input: StoredAgentOperationInputV1::Close {
                        expected_revision: 5,
                    },
                    preparation: None,
                    state: StoredAgentOperationStateV1::Completed(view(
                        6,
                        AgentSessionPhaseV1::Closed,
                    )),
                },
            ],
        }],
    }
}

#[test]
fn canonical_agent_snapshot_roundtrips_and_rejects_truncation_or_trailing_bytes() {
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
fn prior_empty_checkpoint_version_remains_decodable_without_context_claims() {
    let mut bytes = encode(&AgentServiceSnapshotV1::default(), limits()).unwrap();
    bytes[8] = 1;
    assert_eq!(
        decode(&bytes, limits()).unwrap(),
        AgentServiceSnapshotV1::default()
    );
}

#[test]
fn claude_stream_json_wire_profile_roundtrips_without_becoming_acp() {
    let mut snapshot = snapshot();
    snapshot.sessions[0].profile.wire = AgentWireProfileV1::ClaudeAgentStreamJson;
    let bytes = encode(&snapshot, limits()).unwrap();
    assert_eq!(decode(&bytes, limits()).unwrap(), snapshot);
}

#[test]
fn agent_snapshot_order_and_independent_limits_fail_closed() {
    let mut duplicate = snapshot();
    duplicate.sessions.push(duplicate.sessions[0].clone());
    assert!(encode(&duplicate, limits()).is_err());

    let mut too_many = limits();
    too_many.max_operations_per_session = 3;
    assert_eq!(
        encode(&snapshot(), too_many),
        Err(daimon_checkpoint::CodecErrorV1::Limit)
    );
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
            mechanism: "daimon-agent-checkpoint-test",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

#[test]
fn exact_agent_checkpoint_revision_reopens_without_adopting_missing_state() {
    let mut store = CheckpointAgentSessionStore::create(Store::default(), limits()).unwrap();
    assert_eq!(
        store.load_agents().unwrap(),
        Some(AgentServiceSnapshotV1::default())
    );
    assert_eq!(
        store.commit_agents(&snapshot()).unwrap(),
        StoreCommitV1::Committed
    );
    let backend = store.into_inner();
    let mut reopened = CheckpointAgentSessionStore::open_existing(backend, limits()).unwrap();
    assert_eq!(reopened.load_agents().unwrap(), Some(snapshot()));

    let mut missing =
        CheckpointAgentSessionStore::open_existing(Store::default(), limits()).unwrap();
    assert!(missing.load_agents().is_err());
}
