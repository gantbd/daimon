use daimon_harness::{
    AuthorityEvidenceV1, Engine, ExecutionBudgetV1, ExecutionDispositionV1, ExecutionId,
    HarnessProfileId, HarnessRequestV1, IdempotencyKey, Limits, LogicalTime, PrincipalId,
    ProviderReceiptV1, RefusalV1, TaskAttemptRefV1, ToolCapabilityId,
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
