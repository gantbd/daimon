use daimon_protocol::*;
use daimon_wire::*;

fn request_frame() -> RequestFrameV1 {
    RequestFrameV1 {
        session: SessionHandleV1(9),
        command: CommandV1::Execute {
            request: ExecuteRequestV1 {
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
            },
            now: 10,
        },
    }
}

fn assert_mutations<T: Eq + std::fmt::Debug>(
    canonical: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, CodecErrorV1>,
    encode: impl Fn(&T) -> Result<Vec<u8>, CodecErrorV1>,
) {
    let check = |mutated: &[u8]| {
        if let Ok(value) = decode(mutated) {
            assert_eq!(encode(&value).unwrap(), mutated);
        }
    };
    for index in 0..canonical.len() {
        for bit in 0..8 {
            let mut mutated = canonical.to_vec();
            mutated[index] ^= 1 << bit;
            check(&mutated);
        }
        let mut deleted = canonical.to_vec();
        deleted.remove(index);
        check(&deleted);
    }
    for index in 0..=canonical.len() {
        let mut inserted = canonical.to_vec();
        inserted.insert(index, 0xff);
        check(&inserted);
    }
}

#[test]
fn request_reply_and_handshake_mutations_are_refused_or_canonical() {
    let limits = LimitsV1::default();
    let request = request_frame();
    let bytes = encode_request(&request, limits).unwrap();
    assert_mutations(
        &bytes,
        |value| decode_request(value, limits),
        |value| encode_request(value, limits),
    );

    let reply = ReplyV1::Accepted(OutcomeV1::Executed(ExecutionResultV1 {
        execution_id: ExecutionIdV1::new([1; 16]),
        disposition: ExecutionDispositionV1::Completed,
        produced_artifacts: vec![ArtifactReferenceIdV1::new([2; 16])],
        output_bytes: 12,
    }));
    let bytes = encode_reply(&reply, limits).unwrap();
    assert_mutations(
        &bytes,
        |value| decode_reply(value, limits),
        |value| encode_reply(value, limits),
    );

    let bytes = encode_session_opened(SessionHandleV1(9), limits).unwrap();
    assert_mutations(
        &bytes,
        |value| decode_session_opened(value, limits),
        |value| encode_session_opened(*value, limits),
    );
}
