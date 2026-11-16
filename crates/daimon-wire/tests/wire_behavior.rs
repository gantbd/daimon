use daimon_protocol::*;
use daimon_wire::{
    CodecErrorV1, LimitsV1, RequestFrameV1, decode_reply, decode_request, decode_session_opened,
    encode_reply, encode_request, encode_session_opened,
};

fn request() -> ExecuteRequestV1 {
    ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new([1; 16]),
        task_attempt: TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 3,
            attempt_number: 1,
        },
        principal: PrincipalIdV1::new([4; 16]),
        profile: HarnessProfileIdV1::new([5; 16]),
        idempotency_key: IdempotencyKeyV1::new([6; 16]),
        context: vec![ContextReferenceIdV1::new([7; 16])],
        tools: vec![ToolCapabilityIdV1::new([8; 16])],
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 1,
            max_context_bytes: 1_024,
            max_output_bytes: 1_024,
        },
    }
}

#[test]
fn every_request_roundtrips_and_truncation_or_trailing_data_refuses() {
    let frames = [
        RequestFrameV1 {
            session: SessionHandleV1(9),
            command: CommandV1::Execute {
                request: request(),
                now: 10,
            },
        },
        RequestFrameV1 {
            session: SessionHandleV1(9),
            command: CommandV1::Inspect {
                execution_id: ExecutionIdV1::new([1; 16]),
            },
        },
    ];
    for frame in frames {
        let bytes = encode_request(&frame, LimitsV1::default()).unwrap();
        assert_eq!(decode_request(&bytes, LimitsV1::default()).unwrap(), frame);
        for end in 0..bytes.len() {
            assert!(decode_request(&bytes[..end], LimitsV1::default()).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_request(&trailing, LimitsV1::default()).is_err());
    }
}

#[test]
fn every_outcome_disposition_and_refusal_roundtrips() {
    let mut replies = Vec::new();
    for disposition in [
        ExecutionDispositionV1::Completed,
        ExecutionDispositionV1::Failed,
        ExecutionDispositionV1::Cancelled,
        ExecutionDispositionV1::TimedOut,
        ExecutionDispositionV1::Uncertain,
    ] {
        replies.push(ReplyV1::Accepted(OutcomeV1::Executed(ExecutionResultV1 {
            execution_id: ExecutionIdV1::new([1; 16]),
            disposition,
            produced_artifacts: vec![ArtifactReferenceIdV1::new([2; 16])],
            output_bytes: 12,
        })));
    }
    replies.extend([
        ReplyV1::Accepted(OutcomeV1::OutcomeUnknown {
            execution_id: ExecutionIdV1::new([1; 16]),
        }),
        ReplyV1::Accepted(OutcomeV1::Status {
            execution_id: ExecutionIdV1::new([1; 16]),
            phase: ExecutionPhaseV1::OutcomeUnknown,
        }),
        ReplyV1::Accepted(OutcomeV1::Status {
            execution_id: ExecutionIdV1::new([1; 16]),
            phase: ExecutionPhaseV1::Completed,
        }),
    ]);
    for refusal in [
        RefusalV1::UnknownSession,
        RefusalV1::PrincipalMismatch,
        RefusalV1::AuthorityDenied,
        RefusalV1::AuthorityExpired,
        RefusalV1::AttemptDenied,
        RefusalV1::IdempotencyConflict,
        RefusalV1::ExecutionConflict,
        RefusalV1::Capacity,
        RefusalV1::InvalidBudget,
        RefusalV1::BudgetLimit,
        RefusalV1::ToolNotAuthorized,
        RefusalV1::ContextLimit,
        RefusalV1::ToolLimit,
        RefusalV1::ProviderReceiptMismatch,
        RefusalV1::ProviderReceiptConflict,
        RefusalV1::OutputLimit,
        RefusalV1::ArtifactLimit,
        RefusalV1::UnknownExecution,
        RefusalV1::InvalidInput,
        RefusalV1::Exhausted,
    ] {
        replies.push(ReplyV1::Refused(refusal));
    }
    for reply in replies {
        let bytes = encode_reply(&reply, LimitsV1::default()).unwrap();
        assert_eq!(decode_reply(&bytes, LimitsV1::default()).unwrap(), reply);
    }
}

#[test]
fn vector_and_frame_limits_refuse_before_growth() {
    let frame = RequestFrameV1 {
        session: SessionHandleV1(9),
        command: CommandV1::Execute {
            request: request(),
            now: 10,
        },
    };
    let limits = LimitsV1 {
        max_context_references: 0,
        ..LimitsV1::default()
    };
    assert_eq!(encode_request(&frame, limits), Err(CodecErrorV1::Limit));
    let bytes = encode_request(&frame, LimitsV1::default()).unwrap();
    assert_eq!(decode_request(&bytes, limits), Err(CodecErrorV1::Limit));
    assert_eq!(
        decode_request(
            &bytes,
            LimitsV1 {
                max_frame_bytes: bytes.len() - 1,
                ..LimitsV1::default()
            },
        ),
        Err(CodecErrorV1::Limit)
    );
}

#[test]
fn authenticated_session_handshake_is_closed_and_bounded() {
    let bytes = encode_session_opened(SessionHandleV1(42), LimitsV1::default()).unwrap();
    assert_eq!(
        decode_session_opened(&bytes, LimitsV1::default()),
        Ok(SessionHandleV1(42))
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        decode_session_opened(&trailing, LimitsV1::default()),
        Err(CodecErrorV1::Malformed)
    );
}
