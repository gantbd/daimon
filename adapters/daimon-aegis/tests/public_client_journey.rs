use aegis_authority::{EngineId, Limits as AegisLimits, PrincipalId, SessionId};
use aegis_client::{AuthorityClient, ServicePort as AegisServicePort};
use aegis_host::{DurableAuthority, HostError};
use aegis_protocol::{
    ActionV1, CommandV1, EngineNamespaceV1, OutcomeV1, ReplyV1 as AegisReplyV1, ScopeV1,
    SessionHandleV1 as AegisSessionHandleV1,
};
use aegis_service::{
    AuthenticatedSessionV1 as AegisSessionV1, Service as AegisService,
    ServiceLimitsV1 as AegisServiceLimitsV1,
};
use daimon_aegis::{AegisAuthorizer, grant_context};
use daimon_harness::Limits as DaimonLimits;
use daimon_host::{
    AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1, Provider, ProviderOutcomeV1,
    ProviderReceiptV1,
};
use daimon_protocol::{
    CommandV1 as DaimonCommandV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionDispositionV1,
    ExecutionIdV1, HarnessProfileIdV1, IdempotencyKeyV1, OutcomeV1 as DaimonOutcomeV1,
    PrincipalIdV1, ReplyV1 as DaimonReplyV1, TaskAttemptRefV1, ToolCapabilityIdV1,
};
use daimon_service::{Service as DaimonService, ServiceLimitsV1 as DaimonServiceLimitsV1};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::rc::Rc;

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
        let revision = Revision(actual.map_or(0, |revision| revision.0 + 1));
        self.0 = Some(Checkpoint {
            revision,
            bytes: bytes.to_vec(),
            strength: AcknowledgementStrength::Durable,
        });
        Ok(CommitOutcome::Committed(CommitReceipt {
            revision,
            mechanism: "daimon-aegis-test",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

#[derive(Clone)]
struct AegisPort(Rc<RefCell<AegisService<Store>>>);

impl AegisServicePort for AegisPort {
    type Error = HostError<Infallible>;

    fn execute(
        &mut self,
        session: AegisSessionHandleV1,
        command: CommandV1,
    ) -> Result<AegisReplyV1, Self::Error> {
        self.0.borrow_mut().execute(session, command)
    }
}

struct Attempts;

impl AttemptValidator for Attempts {
    fn validate(
        &mut self,
        _session: &AuthenticatedSessionV1,
        _request: &ExecuteRequestV1,
    ) -> Result<(), AttemptRefusalV1> {
        Ok(())
    }
}

struct FakeProvider(Rc<Cell<usize>>);

impl Provider for FakeProvider {
    fn execute(&mut self, request: &ExecuteRequestV1) -> ProviderOutcomeV1 {
        self.0.set(self.0.get() + 1);
        ProviderOutcomeV1::Receipt(ProviderReceiptV1 {
            execution_id: request.execution_id,
            disposition: ExecutionDispositionV1::Completed,
            output_bytes: 12,
            artifacts: vec![],
        })
    }
}

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
        context: vec![],
        tools: vec![ToolCapabilityIdV1::new([7; 16])],
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
fn live_aegis_profile_and_tool_decisions_gate_daimon_and_revocation_blocks_replay() {
    let authority_id = EngineId::new([8; 16]);
    let authority =
        DurableAuthority::create_new(Store::default(), authority_id, AegisLimits::default())
            .unwrap();
    let mut aegis =
        AegisService::new(authority, authority_id, AegisServiceLimitsV1::default()).unwrap();
    let aegis_session = aegis
        .open_session(AegisSessionV1 {
            principal: PrincipalId::new([4; 16]),
            session: SessionId::new([9; 16]),
            administrator: true,
        })
        .unwrap();
    let AegisReplyV1::Accepted(OutcomeV1::GrantIssued(grant)) = aegis
        .execute(
            aegis_session,
            CommandV1::Issue {
                expected_epoch: 0,
                now: 1,
                expires_at: 20,
                scopes: vec![
                    ScopeV1 {
                        engine: EngineNamespaceV1::Daimon,
                        resource: [5; 16],
                        actions: 1 << ActionV1::Execute as u8,
                    },
                    ScopeV1 {
                        engine: EngineNamespaceV1::Daimon,
                        resource: [7; 16],
                        actions: 1 << ActionV1::Execute as u8,
                    },
                ],
            },
        )
        .unwrap()
    else {
        panic!("execute grant expected")
    };
    let aegis = Rc::new(RefCell::new(aegis));
    let provider_calls = Rc::new(Cell::new(0));
    let authorizer = AegisAuthorizer::new(
        AuthorityClient::new(aegis_session, AegisPort(aegis.clone())),
        grant.handle,
        [4; 16],
    );
    let mut daimon = DaimonService::new(
        DaimonLimits::default(),
        DaimonServiceLimitsV1::default(),
        authorizer,
        Attempts,
        FakeProvider(provider_calls.clone()),
    )
    .unwrap();
    let daimon_session = daimon
        .open_session(AuthenticatedSessionV1 {
            principal: [4; 16],
            authority_context: grant_context(grant.handle),
        })
        .unwrap();
    let command = DaimonCommandV1::Execute {
        request: request(),
        now: 10,
    };

    assert!(matches!(
        daimon.execute(daimon_session, command.clone()),
        DaimonReplyV1::Accepted(DaimonOutcomeV1::Executed(_))
    ));
    assert_eq!(provider_calls.get(), 1);

    assert!(matches!(
        aegis
            .borrow_mut()
            .execute(aegis_session, CommandV1::RevokeEpoch { expected_epoch: 0 })
            .unwrap(),
        AegisReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 1 })
    ));
    assert_eq!(
        daimon.execute(daimon_session, command),
        DaimonReplyV1::Refused(daimon_protocol::RefusalV1::AuthorityDenied)
    );
    assert_eq!(provider_calls.get(), 1);
}
