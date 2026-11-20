use daimon_protocol::{agent::*, *};
use daimon_wire::agent::{
    AgentRequestFrameV1, AgentWireCodecErrorV1, AgentWireLimitsV1, decode_agent_reply,
    decode_agent_request, encode_agent_reply, encode_agent_request,
};

fn execution(seed: u8) -> ExecuteRequestV1 {
    ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new([seed; 16]),
        task_attempt: TaskAttemptRefV1 {
            task_key: [seed.wrapping_add(1); 16],
            task_incarnation: 2,
            attempt_number: 3,
        },
        principal: PrincipalIdV1::new([4; 16]),
        profile: HarnessProfileIdV1::new([5; 16]),
        idempotency_key: IdempotencyKeyV1::new([seed.wrapping_add(2); 16]),
        context: vec![ContextReferenceIdV1::new([6; 16])],
        tools: vec![ToolCapabilityIdV1::new([7; 16])],
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: 10,
            max_input_tokens: 11,
            max_output_tokens: 12,
            max_tool_calls: 13,
            max_context_bytes: 14,
            max_output_bytes: 15,
        },
    }
}

fn open_request() -> AgentOpenRequestV1 {
    AgentOpenRequestV1 {
        session: AgentSessionIdV1::new([8; 16]),
        execution: execution(9),
        workspace: [10; 16],
        budget: AgentSessionBudgetV1 {
            max_elapsed_millis: 100,
            max_turns: 4,
            max_events: 20,
            max_event_bytes: 1_024,
            max_prompt_bytes: 2_048,
            max_permission_requests: 3,
        },
    }
}

#[test]
fn every_agent_command_roundtrips_canonically() {
    let session = AgentSessionIdV1::new([8; 16]);
    let turn = AgentTurnIdV1::new([11; 16]);
    let commands = vec![
        AgentCommandV1::Open {
            request: open_request(),
            now: 20,
        },
        AgentCommandV1::Prompt {
            request: AgentTurnRequestV1 {
                session,
                turn,
                expected_revision: 1,
                execution: execution(12),
                prompt_digest: ContentDigestV1::new([13; 32]),
                prompt: b"inspect the boundary".to_vec(),
            },
            now: 21,
        },
        AgentCommandV1::Events {
            session,
            after: Some(3),
            limit: 8,
        },
        AgentCommandV1::Inspect { session },
        AgentCommandV1::Result { session, turn },
        AgentCommandV1::Reattach {
            session,
            expected_revision: 1,
            execution: execution(19),
            now: 22,
        },
        AgentCommandV1::DecidePermission {
            session,
            expected_revision: 2,
            execution: execution(14),
            decision: AgentPermissionDecisionV1 {
                request: AgentPermissionRequestIdV1::new([15; 16]),
                option: AgentPermissionOptionIdV1::new([16; 16]),
            },
            now: 22,
        },
        AgentCommandV1::Advance {
            session,
            turn,
            expected_revision: 3,
            idempotency_key: IdempotencyKeyV1::new([20; 16]),
            now: 23,
        },
        AgentCommandV1::Cancel {
            session,
            turn,
            expected_revision: 3,
            idempotency_key: IdempotencyKeyV1::new([17; 16]),
            now: 24,
        },
        AgentCommandV1::Close {
            session,
            expected_revision: 4,
            idempotency_key: IdempotencyKeyV1::new([18; 16]),
            now: 25,
        },
    ];
    let limits = AgentWireLimitsV1::default();
    for command in commands {
        let frame = AgentRequestFrameV1 {
            service_session: SessionHandleV1(25),
            command,
        };
        let encoded = encode_agent_request(&frame, limits).unwrap();
        assert_eq!(decode_agent_request(&encoded, limits).unwrap(), frame);
        assert_eq!(encode_agent_request(&frame, limits).unwrap(), encoded);
    }
}

#[test]
fn typed_event_page_roundtrips_and_rejects_every_truncation_or_trailing_byte() {
    let turn = AgentTurnIdV1::new([11; 16]);
    let events = vec![
        AgentEventV1::AssistantMessage {
            bytes: b"a".to_vec(),
        },
        AgentEventV1::Thought {
            bytes: b"b".to_vec(),
        },
        AgentEventV1::Plan {
            bytes: b"c".to_vec(),
        },
        AgentEventV1::ToolCall {
            title: b"tool".to_vec(),
            detail: b"detail".to_vec(),
        },
        AgentEventV1::Terminal {
            stream: b"stdout".to_vec(),
            bytes: b"ok".to_vec(),
        },
        AgentEventV1::Permission(AgentPermissionRequestV1 {
            request: AgentPermissionRequestIdV1::new([15; 16]),
            turn,
            capability: b"terminal".to_vec(),
            description: b"run tests".to_vec(),
            options: vec![AgentPermissionOptionV1 {
                id: AgentPermissionOptionIdV1::new([16; 16]),
                kind: AgentPermissionOptionKindV1::AllowOnce,
                label: b"allow once".to_vec(),
            }],
        }),
        AgentEventV1::FileChange {
            path: b"src/lib.rs".to_vec(),
            content_digest: ContentDigestV1::new([19; 32]),
        },
        AgentEventV1::FileRead {
            path: b"Cargo.toml".to_vec(),
            content_digest: ContentDigestV1::new([23; 32]),
            content_bytes: 42,
        },
        AgentEventV1::Usage {
            input_tokens: 20,
            output_tokens: 21,
        },
        AgentEventV1::TurnFinished {
            turn,
            disposition: ExecutionDispositionV1::Completed,
            stop_reason: AgentTurnStopReasonV1::EndTurn,
            output_digest: Some(ContentDigestV1::new([22; 32])),
        },
    ];
    let reply = AgentReplyV1::Accepted(AgentOutcomeV1::Events(AgentEventPageV1 {
        session: AgentSessionIdV1::new([8; 16]),
        entries: events
            .into_iter()
            .enumerate()
            .map(|(cursor, event)| AgentEventRecordV1 {
                cursor: u64::try_from(cursor).unwrap(),
                event,
            })
            .collect(),
        next_after: Some(9),
    }));
    let limits = AgentWireLimitsV1::default();
    let encoded = encode_agent_reply(&reply, limits).unwrap();
    assert_eq!(decode_agent_reply(&encoded, limits).unwrap(), reply);
    for length in 0..encoded.len() {
        assert!(decode_agent_reply(&encoded[..length], limits).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_agent_reply(&trailing, limits),
        Err(AgentWireCodecErrorV1::Malformed)
    );
}

#[test]
fn session_unknown_and_every_refusal_roundtrip() {
    let limits = AgentWireLimitsV1::default();
    let replies = [
        AgentReplyV1::Accepted(AgentOutcomeV1::Result(AgentResultBindingV1 {
            session: AgentSessionIdV1::new([8; 16]),
            turn: AgentTurnIdV1::new([11; 16]),
            execution: ExecutionIdV1::new([12; 16]),
            task_attempt: TaskAttemptRefV1 {
                task_key: [13; 16],
                task_incarnation: 2,
                attempt_number: 3,
            },
            principal: PrincipalIdV1::new([4; 16]),
            profile: HarnessProfileIdV1::new([5; 16]),
            operation: IdempotencyKeyV1::new([14; 16]),
            authority_decision: [15; 16],
            authority_expires_at: 100,
            prompt_digest: ContentDigestV1::new([16; 32]),
            context_manifest_digest: ContentDigestV1::new([17; 32]),
            event_start_cursor: 4,
            terminal_cursor: 9,
            terminal_revision: 6,
            disposition: ExecutionDispositionV1::Completed,
            stop_reason: AgentTurnStopReasonV1::EndTurn,
            output_digest: Some(ContentDigestV1::new([18; 32])),
        })),
        AgentReplyV1::Accepted(AgentOutcomeV1::Session(AgentSessionViewV1 {
            session: AgentSessionIdV1::new([8; 16]),
            revision: 2,
            phase: AgentSessionPhaseV1::ReattachRequired,
            profile_document_digest: ContentDigestV1::new([9; 32]),
            active_turn: None,
            last_event_cursor: None,
            last_context: None,
            capabilities: AgentCapabilitiesV1 {
                resume_session: true,
                ..AgentCapabilitiesV1::default()
            },
        })),
        AgentReplyV1::Accepted(AgentOutcomeV1::Session(AgentSessionViewV1 {
            session: AgentSessionIdV1::new([8; 16]),
            revision: 3,
            phase: AgentSessionPhaseV1::AwaitingPermission,
            profile_document_digest: ContentDigestV1::new([9; 32]),
            active_turn: Some(AgentTurnIdV1::new([11; 16])),
            last_event_cursor: Some(4),
            last_context: Some(AgentContextReceiptV1 {
                execution: ExecutionIdV1::new([12; 16]),
                manifest_digest: ContentDigestV1::new([13; 32]),
                entries: vec![AgentContextManifestEntryV1 {
                    reference: ContextReferenceIdV1::new([6; 16]),
                    kind: ContextKindV1::VellumDocument,
                    source_digest: ContentDigestV1::new([14; 32]),
                    content_bytes: 4_096,
                    grounding: None,
                }],
            }),
            capabilities: AgentCapabilitiesV1 {
                load_session: true,
                resume_session: true,
                permissions: true,
                filesystem_read: true,
                filesystem_write: true,
                terminal: true,
                session_modes: true,
                session_models: true,
            },
        })),
        AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session: AgentSessionIdV1::new([8; 16]),
            idempotency_key: IdempotencyKeyV1::new([12; 16]),
        }),
    ];
    for reply in replies {
        let encoded = encode_agent_reply(&reply, limits).unwrap();
        assert_eq!(decode_agent_reply(&encoded, limits).unwrap(), reply);
    }

    let refusals = [
        AgentRefusalV1::UnknownServiceSession,
        AgentRefusalV1::PrincipalMismatch,
        AgentRefusalV1::UnknownAgentSession,
        AgentRefusalV1::UnknownTurn,
        AgentRefusalV1::UnknownPermissionRequest,
        AgentRefusalV1::UnknownPermissionOption,
        AgentRefusalV1::RevisionConflict,
        AgentRefusalV1::AuthorityDenied,
        AgentRefusalV1::AuthorityExpired,
        AgentRefusalV1::AttemptDenied,
        AgentRefusalV1::IdempotencyConflict,
        AgentRefusalV1::SessionConflict,
        AgentRefusalV1::TurnConflict,
        AgentRefusalV1::ProviderReceiptMismatch,
        AgentRefusalV1::ProviderReceiptConflict,
        AgentRefusalV1::Busy,
        AgentRefusalV1::Capacity,
        AgentRefusalV1::Limit,
        AgentRefusalV1::Unsupported,
        AgentRefusalV1::InvalidInput,
        AgentRefusalV1::Closed,
    ];
    for refusal in refusals {
        let reply = AgentReplyV1::Refused(refusal);
        let encoded = encode_agent_reply(&reply, limits).unwrap();
        assert_eq!(decode_agent_reply(&encoded, limits).unwrap(), reply);
    }
}

#[test]
fn independent_prompt_event_and_option_limits_fail_closed() {
    let mut limits = AgentWireLimitsV1 {
        max_prompt_bytes: 3,
        ..AgentWireLimitsV1::default()
    };
    let frame = AgentRequestFrameV1 {
        service_session: SessionHandleV1(1),
        command: AgentCommandV1::Prompt {
            request: AgentTurnRequestV1 {
                session: AgentSessionIdV1::new([8; 16]),
                turn: AgentTurnIdV1::new([11; 16]),
                expected_revision: 1,
                execution: execution(12),
                prompt_digest: ContentDigestV1::new([13; 32]),
                prompt: b"four".to_vec(),
            },
            now: 1,
        },
    };
    assert_eq!(
        encode_agent_request(&frame, limits),
        Err(AgentWireCodecErrorV1::Limit)
    );

    limits = AgentWireLimitsV1::default();
    limits.max_events = 1;
    let reply = AgentReplyV1::Accepted(AgentOutcomeV1::Events(AgentEventPageV1 {
        session: AgentSessionIdV1::new([8; 16]),
        entries: vec![
            AgentEventRecordV1 {
                cursor: 0,
                event: AgentEventV1::Usage {
                    input_tokens: 1,
                    output_tokens: 2,
                },
            },
            AgentEventRecordV1 {
                cursor: 1,
                event: AgentEventV1::Usage {
                    input_tokens: 3,
                    output_tokens: 4,
                },
            },
        ],
        next_after: None,
    }));
    assert_eq!(
        encode_agent_reply(&reply, limits),
        Err(AgentWireCodecErrorV1::Limit)
    );
}

#[test]
fn prior_agent_wire_profile_is_rejected_instead_of_reinterpreted() {
    let limits = AgentWireLimitsV1::default();
    let mut encoded = encode_agent_request(
        &AgentRequestFrameV1 {
            service_session: SessionHandleV1(1),
            command: AgentCommandV1::Inspect {
                session: AgentSessionIdV1::new([8; 16]),
            },
        },
        limits,
    )
    .unwrap();
    encoded[7] = b'1';
    assert_eq!(
        decode_agent_request(&encoded, limits),
        Err(AgentWireCodecErrorV1::Unsupported)
    );
}
