use daimon_protocol::*;
use daimon_wire::*;

fn request() -> ExecuteRequestV1 {
    ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new([1; 16]),
        task_attempt: TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 3,
            attempt_number: 4,
        },
        principal: PrincipalIdV1::new([5; 16]),
        profile: HarnessProfileIdV1::new([6; 16]),
        idempotency_key: IdempotencyKeyV1::new([7; 16]),
        context: vec![ContextReferenceIdV1::new([8; 16])],
        tools: vec![],
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 50,
            max_tool_calls: 0,
            max_context_bytes: 4_096,
            max_output_bytes: 2_048,
        },
    }
}

fn result() -> ModelExecutionResultV1 {
    ModelExecutionResultV1 {
        execution_id: ExecutionIdV1::new([1; 16]),
        disposition: ExecutionDispositionV1::Completed,
        evidence_digest: ContentDigestV1::new([9; 32]),
        invocation_evidence: Some(Box::new(ModelInvocationEvidenceV1 {
            provider: ProviderProfileIdV1::new([21; 16]),
            provider_document_digest: ContentDigestV1::new([22; 32]),
            model_digest: ContentDigestV1::new([23; 32]),
            context_manifest_digest: ContentDigestV1::new([24; 32]),
            message_manifest_digest: ContentDigestV1::new([25; 32]),
            evidence_scope_digest: ContentDigestV1::new([26; 32]),
        })),
        input_tokens: 42,
        output_tokens: 17,
        output: b"bounded answer".to_vec(),
        proposals: vec![
            OutputProposalV1::AgoraMessage(AgoraMessageProposalV1 {
                room: [10; 16],
                reply_to: [11; 16],
                body: b"reply".to_vec(),
            }),
            OutputProposalV1::VellumEdit(VellumEditProposalV1 {
                workspace: [12; 16],
                document: [13; 16],
                expected_revision: 14,
                replacement: b"replacement".to_vec(),
            }),
        ],
    }
}

fn tool_result() -> ModelExecutionResultV1 {
    let mut value = result();
    value
        .proposals
        .push(OutputProposalV1::ToolCall(ToolCallProposalV1 {
            request: [15; 16],
            capability: ToolCapabilityIdV1::new([16; 16]),
            provider_correlation: b"call-15".to_vec(),
            arguments: br#"{"path":"README.md"}"#.to_vec(),
        }));
    value
}

fn legacy_tool_result() -> ModelExecutionResultV1 {
    let mut value = tool_result();
    value.invocation_evidence = None;
    value
}

#[test]
fn model_requests_use_an_independent_frame_family() {
    let limits = ModelLimitsV1::default();
    let frames = [
        ModelRequestFrameV1 {
            session: SessionHandleV1(15),
            command: ModelCommandV1::Execute {
                request: request(),
                now: 16,
            },
        },
        ModelRequestFrameV1 {
            session: SessionHandleV1(15),
            command: ModelCommandV1::Inspect {
                execution_id: ExecutionIdV1::new([1; 16]),
            },
        },
        ModelRequestFrameV1 {
            session: SessionHandleV1(15),
            command: ModelCommandV1::Resume {
                request: request(),
                source_execution: ExecutionIdV1::new([17; 16]),
                results: vec![ResumeToolResultV1 {
                    request: [18; 16],
                    evidence_digest: ContentDigestV1::new([19; 32]),
                    output_digest: ContentDigestV1::new([20; 32]),
                    output: b"tool output".to_vec(),
                }],
                now: 16,
            },
        },
    ];
    for frame in frames {
        let bytes = encode_model_request(&frame, limits).unwrap();
        assert_eq!(decode_model_request(&bytes, limits).unwrap(), frame);
        assert_eq!(
            decode_request(&bytes, LimitsV1::default()),
            Err(CodecErrorV1::Unsupported)
        );
        for end in 0..bytes.len() {
            assert!(decode_model_request(&bytes[..end], limits).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_model_request(&trailing, limits),
            Err(CodecErrorV1::Malformed)
        );
    }
}

#[test]
fn typed_model_results_and_statuses_roundtrip() {
    let limits = ModelLimitsV1::default();
    let replies = [
        ModelReplyV1::Accepted(ModelOutcomeV1::Executed(result())),
        ModelReplyV1::Accepted(ModelOutcomeV1::OutcomeUnknown {
            execution_id: ExecutionIdV1::new([1; 16]),
        }),
        ModelReplyV1::Accepted(ModelOutcomeV1::Status {
            execution_id: ExecutionIdV1::new([1; 16]),
            phase: ExecutionPhaseV1::Completed,
        }),
        ModelReplyV1::Refused(RefusalV1::ProviderReceiptConflict),
    ];
    for reply in replies {
        let bytes = encode_model_reply(&reply, limits).unwrap();
        assert_eq!(decode_model_reply(&bytes, limits).unwrap(), reply);
        assert_eq!(
            decode_reply(&bytes, LimitsV1::default()),
            Err(CodecErrorV1::Unsupported)
        );
    }
}

#[test]
fn native_tool_calls_use_the_additive_model_reply_family() {
    let limits = ModelLimitsV1::default();
    let reply = ModelReplyV1::Accepted(ModelOutcomeV1::Executed(tool_result()));
    let bytes = encode_model_reply(&reply, limits).unwrap();
    assert_eq!(bytes[8], 8);
    assert_eq!(decode_model_reply(&bytes, limits).unwrap(), reply);

    let mut falsely_legacy = bytes;
    falsely_legacy[8] = 5;
    assert!(decode_model_reply(&falsely_legacy, limits).is_err());
}

#[test]
fn preceding_native_tool_reply_family_remains_decodable_but_has_no_resume_correlation() {
    let limits = ModelLimitsV1::default();
    let reply = ModelReplyV1::Accepted(ModelOutcomeV1::Executed(legacy_tool_result()));
    let mut bytes = encode_model_reply(&reply, limits).unwrap();
    let marker = b"call-15";
    let start = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    assert_eq!(
        &bytes[start - 4..start],
        &(marker.len() as u32).to_be_bytes()
    );
    bytes.drain(start - 4..start + marker.len());
    bytes[8] = 6;

    let ModelReplyV1::Accepted(ModelOutcomeV1::Executed(decoded)) =
        decode_model_reply(&bytes, limits).unwrap()
    else {
        panic!("expected decoded model result")
    };
    let OutputProposalV1::ToolCall(call) = &decoded.proposals[2] else {
        panic!("expected decoded tool proposal")
    };
    assert!(call.provider_correlation.is_empty());
}

#[test]
fn output_and_proposal_limits_refuse_before_allocation() {
    let reply = ModelReplyV1::Accepted(ModelOutcomeV1::Executed(result()));
    let bytes = encode_model_reply(&reply, ModelLimitsV1::default()).unwrap();

    for limits in [
        ModelLimitsV1 {
            max_output_bytes: 1,
            ..ModelLimitsV1::default()
        },
        ModelLimitsV1 {
            max_proposals: 1,
            ..ModelLimitsV1::default()
        },
        ModelLimitsV1 {
            max_proposal_bytes: 1,
            ..ModelLimitsV1::default()
        },
    ] {
        assert_eq!(encode_model_reply(&reply, limits), Err(CodecErrorV1::Limit));
        assert_eq!(decode_model_reply(&bytes, limits), Err(CodecErrorV1::Limit));
    }
}

#[test]
fn model_mutations_are_refused_or_canonical() {
    let limits = ModelLimitsV1::default();
    let reply = ModelReplyV1::Accepted(ModelOutcomeV1::Executed(result()));
    let canonical = encode_model_reply(&reply, limits).unwrap();
    for index in 0..canonical.len() {
        for bit in 0..8 {
            let mut mutated = canonical.clone();
            mutated[index] ^= 1 << bit;
            if let Ok(value) = decode_model_reply(&mutated, limits) {
                assert_eq!(encode_model_reply(&value, limits).unwrap(), mutated);
            }
        }
    }
}
