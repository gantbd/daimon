use daimon_harness::Limits;
use daimon_host::{
    AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1, AuthorityGrantV1,
    AuthorityRefusalV1, ExecutionAuthorizer, ExecutionStore, Provider, ProviderOutcomeV1,
    ProviderReceiptV1, ServiceSnapshotV1, StoreCommitV1,
};
use daimon_protocol::{
    CommandV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionDispositionV1, ExecutionIdV1,
    ExecutionPhaseV1, HarnessProfileIdV1, IdempotencyKeyV1, OutcomeV1, PrincipalIdV1, ReplyV1,
    TaskAttemptRefV1, ToolCapabilityIdV1,
};
use daimon_service::{Service, ServiceLimitsV1};
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Clone)]
struct Authorizer {
    calls: Rc<Cell<usize>>,
    allowed: Rc<Cell<bool>>,
}

impl ExecutionAuthorizer for Authorizer {
    fn authorize(
        &mut self,
        _session: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
        _now: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
        self.calls.set(self.calls.get() + 1);
        if !self.allowed.get() {
            return Err(AuthorityRefusalV1::Denied);
        }
        Ok(AuthorityGrantV1 {
            decision_id: [8; 16],
            expires_at: 20,
            tools: request.tools.clone(),
        })
    }
}

#[derive(Clone)]
struct Attempts(Rc<Cell<usize>>);

impl AttemptValidator for Attempts {
    fn validate(
        &mut self,
        _session: &AuthenticatedSessionV1,
        _request: &ExecuteRequestV1,
    ) -> Result<(), AttemptRefusalV1> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}

struct FakeProvider {
    calls: Rc<Cell<usize>>,
    unknown: bool,
}

impl Provider for FakeProvider {
    fn execute(&mut self, request: &ExecuteRequestV1) -> ProviderOutcomeV1 {
        self.calls.set(self.calls.get() + 1);
        if self.unknown {
            ProviderOutcomeV1::OutcomeUnknown
        } else {
            ProviderOutcomeV1::Receipt(ProviderReceiptV1 {
                execution_id: request.execution_id,
                disposition: ExecutionDispositionV1::Completed,
                output_bytes: 12,
                artifacts: vec![],
            })
        }
    }
}

fn request(execution: u8, key: u8) -> ExecuteRequestV1 {
    ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new([execution; 16]),
        task_attempt: TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 3,
            attempt_number: 1,
        },
        principal: PrincipalIdV1::new([4; 16]),
        profile: HarnessProfileIdV1::new([5; 16]),
        idempotency_key: IdempotencyKeyV1::new([key; 16]),
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
    }
}

struct Fixture {
    service: Service<Authorizer, Attempts, FakeProvider>,
    authority_calls: Rc<Cell<usize>>,
    attempt_calls: Rc<Cell<usize>>,
    provider_calls: Rc<Cell<usize>>,
    allowed: Rc<Cell<bool>>,
}

fn service(unknown: bool) -> Fixture {
    let authority_calls = Rc::new(Cell::new(0));
    let attempt_calls = Rc::new(Cell::new(0));
    let provider_calls = Rc::new(Cell::new(0));
    let allowed = Rc::new(Cell::new(true));
    let service = Service::new(
        Limits::default(),
        ServiceLimitsV1::default(),
        Authorizer {
            calls: authority_calls.clone(),
            allowed: allowed.clone(),
        },
        Attempts(attempt_calls.clone()),
        FakeProvider {
            calls: provider_calls.clone(),
            unknown,
        },
    )
    .unwrap();
    Fixture {
        service,
        authority_calls,
        attempt_calls,
        provider_calls,
        allowed,
    }
}

fn open(
    service: &mut Service<Authorizer, Attempts, FakeProvider>,
) -> daimon_protocol::SessionHandleV1 {
    service
        .open_session(AuthenticatedSessionV1 {
            principal: [4; 16],
            authority_context: [9; 16],
        })
        .unwrap()
}

#[test]
fn matching_replay_reauthorizes_without_redispatching_provider_or_attempt() {
    let mut fixture = service(false);
    let session = open(&mut fixture.service);
    let command = CommandV1::Execute {
        request: request(1, 7),
        now: 10,
    };

    let first = fixture.service.execute(session, command.clone());
    assert!(matches!(first, ReplyV1::Accepted(OutcomeV1::Executed(_))));
    assert_eq!(fixture.service.execute(session, command), first);
    assert_eq!(fixture.authority_calls.get(), 2);
    assert_eq!(fixture.attempt_calls.get(), 1);
    assert_eq!(fixture.provider_calls.get(), 1);
}

#[test]
fn uncertain_provider_call_is_fenced_and_never_automatically_retried() {
    let mut fixture = service(true);
    let session = open(&mut fixture.service);
    let command = CommandV1::Execute {
        request: request(1, 7),
        now: 10,
    };

    let unknown = ReplyV1::Accepted(OutcomeV1::OutcomeUnknown {
        execution_id: ExecutionIdV1::new([1; 16]),
    });
    assert_eq!(fixture.service.execute(session, command.clone()), unknown);
    assert_eq!(fixture.service.execute(session, command), unknown);
    assert_eq!(fixture.provider_calls.get(), 1);
    assert_eq!(fixture.attempt_calls.get(), 1);
    assert_eq!(fixture.authority_calls.get(), 2);
    assert_eq!(
        fixture.service.execute(
            session,
            CommandV1::Inspect {
                execution_id: ExecutionIdV1::new([1; 16]),
            },
        ),
        ReplyV1::Accepted(OutcomeV1::Status {
            execution_id: ExecutionIdV1::new([1; 16]),
            phase: ExecutionPhaseV1::OutcomeUnknown,
        })
    );
}

#[test]
fn retained_result_delivery_requires_current_authority() {
    let mut fixture = service(false);
    let session = open(&mut fixture.service);
    let command = CommandV1::Execute {
        request: request(1, 7),
        now: 10,
    };
    assert!(matches!(
        fixture.service.execute(session, command.clone()),
        ReplyV1::Accepted(OutcomeV1::Executed(_))
    ));

    fixture.allowed.set(false);
    assert_eq!(
        fixture.service.execute(session, command),
        ReplyV1::Refused(daimon_protocol::RefusalV1::AuthorityDenied)
    );
    assert_eq!(fixture.authority_calls.get(), 2);
    assert_eq!(fixture.attempt_calls.get(), 1);
    assert_eq!(fixture.provider_calls.get(), 1);
}

#[test]
fn idempotency_and_execution_aliases_refuse_without_a_second_provider_call() {
    let mut fixture = service(false);
    let session = open(&mut fixture.service);
    assert!(matches!(
        fixture.service.execute(
            session,
            CommandV1::Execute {
                request: request(1, 7),
                now: 10,
            },
        ),
        ReplyV1::Accepted(OutcomeV1::Executed(_))
    ));
    assert_eq!(
        fixture.service.execute(
            session,
            CommandV1::Execute {
                request: request(2, 7),
                now: 10,
            },
        ),
        ReplyV1::Refused(daimon_protocol::RefusalV1::IdempotencyConflict)
    );
    let mut changed = request(1, 8);
    changed.budget.max_output_bytes = 512;
    assert_eq!(
        fixture.service.execute(
            session,
            CommandV1::Execute {
                request: changed,
                now: 10,
            },
        ),
        ReplyV1::Refused(daimon_protocol::RefusalV1::ExecutionConflict)
    );
    assert_eq!(fixture.attempt_calls.get(), 2);
    assert_eq!(fixture.provider_calls.get(), 1);
}

#[test]
fn execution_status_is_visible_only_to_the_bound_principal() {
    let mut fixture = service(true);
    let owner = open(&mut fixture.service);
    fixture.service.execute(
        owner,
        CommandV1::Execute {
            request: request(1, 7),
            now: 10,
        },
    );
    let foreign = fixture
        .service
        .open_session(AuthenticatedSessionV1 {
            principal: [3; 16],
            authority_context: [9; 16],
        })
        .unwrap();

    assert_eq!(
        fixture.service.execute(
            foreign,
            CommandV1::Inspect {
                execution_id: ExecutionIdV1::new([1; 16]),
            },
        ),
        ReplyV1::Refused(daimon_protocol::RefusalV1::PrincipalMismatch)
    );
}

#[derive(Clone, Copy)]
enum CommitBehavior {
    Committed,
    IndeterminateSave,
}

#[derive(Default)]
struct StoreState {
    snapshot: Option<ServiceSnapshotV1>,
    behaviors: VecDeque<CommitBehavior>,
}

#[derive(Clone, Default)]
struct SharedStore(Rc<RefCell<StoreState>>);

impl ExecutionStore for SharedStore {
    type Error = ();

    fn load(&mut self) -> Result<Option<ServiceSnapshotV1>, Self::Error> {
        Ok(self.0.borrow().snapshot.clone())
    }

    fn commit(&mut self, snapshot: &ServiceSnapshotV1) -> Result<StoreCommitV1, Self::Error> {
        let mut state = self.0.borrow_mut();
        let behavior = state
            .behaviors
            .pop_front()
            .unwrap_or(CommitBehavior::Committed);
        state.snapshot = Some(snapshot.clone());
        Ok(match behavior {
            CommitBehavior::Committed => StoreCommitV1::Committed,
            CommitBehavior::IndeterminateSave => StoreCommitV1::Indeterminate,
        })
    }
}

fn durable_service(
    store: SharedStore,
    provider_calls: Rc<Cell<usize>>,
) -> Service<Authorizer, Attempts, FakeProvider, SharedStore> {
    Service::open(
        Limits::default(),
        ServiceLimitsV1::default(),
        Authorizer {
            calls: Rc::new(Cell::new(0)),
            allowed: Rc::new(Cell::new(true)),
        },
        Attempts(Rc::new(Cell::new(0))),
        FakeProvider {
            calls: provider_calls,
            unknown: false,
        },
        store,
    )
    .unwrap()
}

fn open_durable(
    service: &mut Service<Authorizer, Attempts, FakeProvider, SharedStore>,
) -> daimon_protocol::SessionHandleV1 {
    service
        .open_session(AuthenticatedSessionV1 {
            principal: [4; 16],
            authority_context: [9; 16],
        })
        .unwrap()
}

#[test]
fn completed_result_reopens_and_replays_without_provider_redispatch() {
    let store = SharedStore::default();
    let provider_calls = Rc::new(Cell::new(0));
    let command = CommandV1::Execute {
        request: request(1, 7),
        now: 10,
    };
    let mut first = durable_service(store.clone(), provider_calls.clone());
    let session = open_durable(&mut first);
    let result = first.execute(session, command.clone());
    assert!(matches!(result, ReplyV1::Accepted(OutcomeV1::Executed(_))));
    drop(first);

    let mut reopened = durable_service(store, provider_calls.clone());
    let session = open_durable(&mut reopened);
    assert_eq!(reopened.execute(session, command), result);
    assert_eq!(provider_calls.get(), 1);
}

#[test]
fn indeterminate_marker_commit_fences_before_provider_and_survives_reopen() {
    let store = SharedStore::default();
    store
        .0
        .borrow_mut()
        .behaviors
        .push_back(CommitBehavior::IndeterminateSave);
    let provider_calls = Rc::new(Cell::new(0));
    let command = CommandV1::Execute {
        request: request(1, 7),
        now: 10,
    };
    let unknown = ReplyV1::Accepted(OutcomeV1::OutcomeUnknown {
        execution_id: ExecutionIdV1::new([1; 16]),
    });
    let mut first = durable_service(store.clone(), provider_calls.clone());
    let session = open_durable(&mut first);
    assert_eq!(first.execute(session, command.clone()), unknown);
    assert_eq!(provider_calls.get(), 0);
    drop(first);

    let mut reopened = durable_service(store, provider_calls.clone());
    let session = open_durable(&mut reopened);
    assert_eq!(reopened.execute(session, command), unknown);
    assert_eq!(provider_calls.get(), 0);
}

#[test]
fn lost_result_commit_reply_reopens_the_exact_result_without_redispatch() {
    let store = SharedStore::default();
    {
        let mut state = store.0.borrow_mut();
        state.behaviors.push_back(CommitBehavior::Committed);
        state.behaviors.push_back(CommitBehavior::IndeterminateSave);
    }
    let provider_calls = Rc::new(Cell::new(0));
    let command = CommandV1::Execute {
        request: request(1, 7),
        now: 10,
    };
    let mut first = durable_service(store.clone(), provider_calls.clone());
    let session = open_durable(&mut first);
    assert!(matches!(
        first.execute(session, command.clone()),
        ReplyV1::Accepted(OutcomeV1::OutcomeUnknown { .. })
    ));
    assert_eq!(provider_calls.get(), 1);
    drop(first);

    let mut reopened = durable_service(store, provider_calls.clone());
    let session = open_durable(&mut reopened);
    assert!(matches!(
        reopened.execute(session, command),
        ReplyV1::Accepted(OutcomeV1::Executed(_))
    ));
    assert_eq!(provider_calls.get(), 1);
}
