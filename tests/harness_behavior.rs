use daimon_harness::{
    AgoraMessageProposalV1, AuthorityEvidenceV1, ContentDigestV1, ContextEvidenceV1, ContextKindV1,
    ContextReferenceId, Engine, ExecutionBudgetV1, ExecutionDispositionV1, ExecutionId,
    GroundingDepthV1, GroundingEvidenceV1, HarnessProfileId, HarnessRequestV1, IdempotencyKey,
    Limits, LogicalTime, MessageRoleV1, ModelCompletionReceiptV1, ModelContinuationV1,
    ModelMessageV1, ModelToolResultV1, OutputProposalV1, PrincipalId, ProviderProfileId,
    ProviderProfileSnapshotV1, ProviderReceiptV1, ProviderWireProfileV1, RefusalV1,
    TaskAttemptRefV1, ToolCallProposalV1, ToolCapabilityId, VellumEditProposalV1,
};

fn request(key: [u8; 16], tool: [u8; 16]) -> HarnessRequestV1 {
    HarnessRequestV1::new(
        ExecutionId::new([1; 16]),
        TaskAttemptRefV1::new([2; 16], 3, 1),
        PrincipalId::new([4; 16]),
        HarnessProfileId::new([5; 16]),
        IdempotencyKey::new(key),
        vec![],
        vec![ToolCapabilityId::new(tool)],
        ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 1,
            max_context_bytes: 1_024,
            max_output_bytes: 1_024,
        },
    )
}

fn model_request() -> HarnessRequestV1 {
    let mut request = request([7; 16], [6; 16]);
    request.context = vec![
        ContextReferenceId::new([10; 16]),
        ContextReferenceId::new([11; 16]),
    ];
    request
}

fn provider(digest: u8) -> ProviderProfileSnapshotV1 {
    ProviderProfileSnapshotV1::try_new(
        ProviderProfileId::new([12; 16]),
        HarnessProfileId::new([5; 16]),
        ProviderWireProfileV1::OpenAiChatCompletions,
        b"local-model".to_vec(),
        false,
        ContentDigestV1::new([digest; 32]),
    )
    .unwrap()
}

fn tool_provider(digest: u8) -> ProviderProfileSnapshotV1 {
    ProviderProfileSnapshotV1::try_new(
        ProviderProfileId::new([12; 16]),
        HarnessProfileId::new([5; 16]),
        ProviderWireProfileV1::OpenAiChatCompletions,
        b"local-model".to_vec(),
        true,
        ContentDigestV1::new([digest; 32]),
    )
    .unwrap()
}

fn context() -> Vec<ContextEvidenceV1> {
    vec![
        ContextEvidenceV1 {
            reference: ContextReferenceId::new([10; 16]),
            kind: ContextKindV1::AgoraMessage,
            bytes: b"question".to_vec(),
            source_digest: ContentDigestV1::new([21; 32]),
            grounding: None,
        },
        ContextEvidenceV1 {
            reference: ContextReferenceId::new([11; 16]),
            kind: ContextKindV1::DendriteGrounding,
            bytes: b"grounding".to_vec(),
            source_digest: ContentDigestV1::new([22; 32]),
            grounding: Some(GroundingEvidenceV1 {
                depth: GroundingDepthV1::Activated,
                grounding_digest: ContentDigestV1::new([22; 32]),
                surface_digest: ContentDigestV1::new([23; 32]),
            }),
        },
    ]
}

#[test]
fn preparation_is_budgeted_authorized_and_idempotent() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [8; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(20),
    );
    let initial_request = request([7; 16], [6; 16]);

    let first = engine
        .prepare(initial_request.clone(), &authority, LogicalTime(10))
        .unwrap();
    let replay = engine
        .prepare(initial_request, &authority, LogicalTime(10))
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(engine.in_flight(), 1);

    assert_eq!(
        engine.prepare(request([7; 16], [9; 16]), &authority, LogicalTime(10)),
        Err(RefusalV1::IdempotencyConflict)
    );
    assert_eq!(engine.in_flight(), 1);
}

#[test]
fn unauthorized_tools_and_expired_authority_refuse_before_execution_state() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [8; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(10),
    );

    assert_eq!(
        engine.prepare(request([1; 16], [9; 16]), &authority, LogicalTime(9)),
        Err(RefusalV1::ToolNotAuthorized)
    );
    assert_eq!(
        engine.prepare(request([2; 16], [6; 16]), &authority, LogicalTime(10)),
        Err(RefusalV1::AuthorityExpired)
    );
    assert_eq!(engine.in_flight(), 0);
}

#[test]
fn exact_provider_evidence_completes_once_and_matching_replay_is_an_identity() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [8; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(20),
    );
    let prepared = engine
        .prepare(request([7; 16], [6; 16]), &authority, LogicalTime(10))
        .unwrap();
    let receipt = ProviderReceiptV1::new(
        ExecutionId::new([1; 16]),
        ExecutionDispositionV1::Completed,
        12,
        vec![],
    );

    let first = engine.dispatch(prepared.clone(), receipt.clone()).unwrap();
    assert_eq!(engine.in_flight(), 0);
    assert_eq!(engine.completed(), 1);
    assert_eq!(engine.dispatch(prepared, receipt).unwrap(), first);
    assert_eq!(engine.completed(), 1);
}

#[test]
fn authority_and_prepared_debug_surfaces_redact_evidence() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [0x88; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(20),
    );
    let prepared = engine
        .prepare(request([7; 16], [6; 16]), &authority, LogicalTime(10))
        .unwrap();

    assert!(!format!("{authority:?}").contains("136"));
    assert!(!format!("{prepared:?}").contains("136"));
}

#[test]
fn typed_model_dispatch_binds_profile_context_usage_and_peer_proposals() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [8; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(20),
    );
    let prepared = engine
        .prepare(model_request(), &authority, LogicalTime(10))
        .unwrap();
    let invocation = engine
        .prepare_model_invocation(
            &prepared,
            provider(30),
            context(),
            vec![ModelMessageV1 {
                role: MessageRoleV1::User,
                content: b"question".to_vec(),
            }],
            12,
        )
        .unwrap();
    let receipt = ModelCompletionReceiptV1 {
        execution_id: ExecutionId::new([1; 16]),
        provider_document_digest: ContentDigestV1::new([30; 32]),
        evidence_digest: ContentDigestV1::new([31; 32]),
        disposition: ExecutionDispositionV1::Completed,
        input_tokens: 12,
        output_tokens: 8,
        output: b"done".to_vec(),
        proposals: vec![
            OutputProposalV1::AgoraMessage(AgoraMessageProposalV1 {
                room: [40; 16],
                reply_to: [41; 16],
                body: b"answer".to_vec(),
            }),
            OutputProposalV1::VellumEdit(VellumEditProposalV1 {
                workspace: [42; 16],
                document: [43; 16],
                expected_revision: 7,
                replacement: b"revision guarded edit".to_vec(),
            }),
        ],
    };

    let first = engine
        .dispatch_model(prepared.clone(), &invocation, receipt.clone())
        .unwrap();
    assert_eq!(first.proposals, receipt.proposals);
    assert_eq!(first.evidence_digest, ContentDigestV1::new([31; 32]));
    assert_eq!(engine.in_flight(), 0);
    assert_eq!(engine.completed(), 1);
    assert_eq!(
        engine
            .dispatch_model(prepared, &invocation, receipt)
            .unwrap(),
        first
    );
}

#[test]
fn native_tool_proposals_require_requested_capabilities_unique_requests_and_budget() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [8; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(20),
    );
    let prepared = engine
        .prepare(model_request(), &authority, LogicalTime(10))
        .unwrap();
    let invocation = engine
        .prepare_model_invocation(&prepared, tool_provider(30), context(), vec![], 12)
        .unwrap();
    let receipt = |proposals| ModelCompletionReceiptV1 {
        execution_id: ExecutionId::new([1; 16]),
        provider_document_digest: ContentDigestV1::new([30; 32]),
        evidence_digest: ContentDigestV1::new([31; 32]),
        disposition: ExecutionDispositionV1::Completed,
        input_tokens: 12,
        output_tokens: 8,
        output: Vec::new(),
        proposals,
    };
    let call = |request, capability| {
        OutputProposalV1::ToolCall(ToolCallProposalV1 {
            request: [request; 16],
            capability: ToolCapabilityId::new([capability; 16]),
            provider_correlation: b"call-1".to_vec(),
            arguments: br#"{"path":"README.md"}"#.to_vec(),
        })
    };

    let mut missing_correlation = call(1, 6);
    let OutputProposalV1::ToolCall(value) = &mut missing_correlation else {
        unreachable!()
    };
    value.provider_correlation.clear();
    assert_eq!(
        engine.dispatch_model(
            prepared.clone(),
            &invocation,
            receipt(vec![missing_correlation])
        ),
        Err(RefusalV1::ToolCallMismatch)
    );

    assert_eq!(
        engine.dispatch_model(prepared.clone(), &invocation, receipt(vec![call(1, 9)])),
        Err(RefusalV1::ToolCallMismatch)
    );
    assert_eq!(
        engine.dispatch_model(
            prepared.clone(),
            &invocation,
            receipt(vec![call(1, 6), call(1, 6)])
        ),
        Err(RefusalV1::DuplicateToolCall)
    );
    assert_eq!(
        engine.dispatch_model(prepared, &invocation, receipt(vec![call(1, 6), call(2, 6)])),
        Err(RefusalV1::ToolCallLimit)
    );
    assert_eq!(engine.in_flight(), 1);
}

#[test]
fn model_invocation_requires_exact_context_set_and_grounding_shape() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [8; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(20),
    );
    let prepared = engine
        .prepare(model_request(), &authority, LogicalTime(10))
        .unwrap();
    let mut incomplete = context();
    incomplete.pop();
    assert_eq!(
        engine.prepare_model_invocation(&prepared, provider(30), incomplete, vec![], 1),
        Err(RefusalV1::ContextEvidenceMismatch)
    );

    let mut invalid_grounding = context();
    invalid_grounding[1].grounding = None;
    assert_eq!(
        engine.prepare_model_invocation(&prepared, provider(30), invalid_grounding, vec![], 1),
        Err(RefusalV1::ContextEvidenceMismatch)
    );
}

#[test]
fn model_continuation_binds_exact_native_calls_and_bounded_results() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [8; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(20),
    );
    let prepared = engine
        .prepare(model_request(), &authority, LogicalTime(10))
        .unwrap();
    let continuation = ModelContinuationV1 {
        source_execution: ExecutionId::new([9; 16]),
        source_output: Vec::new(),
        source_tools: vec![ToolCapabilityId::new([6; 16])],
        results: vec![ModelToolResultV1 {
            request: [10; 16],
            capability: ToolCapabilityId::new([6; 16]),
            provider_correlation: b"call-10".to_vec(),
            arguments: br#"{"path":"README.md"}"#.to_vec(),
            evidence_digest: ContentDigestV1::new([11; 32]),
            output_digest: ContentDigestV1::new([12; 32]),
            output: b"contents".to_vec(),
        }],
    };
    let invocation = engine
        .prepare_model_continuation(
            &prepared,
            tool_provider(30),
            context(),
            vec![],
            12,
            continuation.clone(),
        )
        .unwrap();
    assert_eq!(invocation.continuation, Some(continuation.clone()));

    let mut invalid = continuation;
    invalid.results[0].provider_correlation.clear();
    assert_eq!(
        engine.prepare_model_continuation(
            &prepared,
            tool_provider(30),
            context(),
            vec![],
            12,
            invalid,
        ),
        Err(RefusalV1::ToolCallMismatch)
    );
}

#[test]
fn model_dispatch_refuses_profile_drift_and_observed_budget_overrun() {
    let mut engine = Engine::try_new(Limits::default()).unwrap();
    let authority = AuthorityEvidenceV1::new(
        [8; 16],
        PrincipalId::new([4; 16]),
        [ToolCapabilityId::new([6; 16])],
        LogicalTime(20),
    );
    let prepared = engine
        .prepare(model_request(), &authority, LogicalTime(10))
        .unwrap();
    let invocation = engine
        .prepare_model_invocation(&prepared, provider(30), context(), vec![], 12)
        .unwrap();
    let receipt = ModelCompletionReceiptV1 {
        execution_id: ExecutionId::new([1; 16]),
        provider_document_digest: ContentDigestV1::new([99; 32]),
        evidence_digest: ContentDigestV1::new([31; 32]),
        disposition: ExecutionDispositionV1::Completed,
        input_tokens: 12,
        output_tokens: 8,
        output: b"done".to_vec(),
        proposals: vec![],
    };
    assert_eq!(
        engine.dispatch_model(prepared.clone(), &invocation, receipt),
        Err(RefusalV1::ProviderProfileMismatch)
    );

    let overrun = ModelCompletionReceiptV1 {
        execution_id: ExecutionId::new([1; 16]),
        provider_document_digest: ContentDigestV1::new([30; 32]),
        evidence_digest: ContentDigestV1::new([31; 32]),
        disposition: ExecutionDispositionV1::Completed,
        input_tokens: 12,
        output_tokens: 101,
        output: b"done".to_vec(),
        proposals: vec![],
    };
    assert_eq!(
        engine.dispatch_model(prepared, &invocation, overrun),
        Err(RefusalV1::OutputTokenLimit)
    );
    assert_eq!(engine.in_flight(), 1);
}
