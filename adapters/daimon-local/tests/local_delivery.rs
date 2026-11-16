#![cfg(unix)]

use daimon_harness::Limits;
use daimon_host::agent::{AgentServiceSnapshotV1, AgentSessionStore};
use daimon_host::{
    AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1, AuthorityGrantV1,
    AuthorityRefusalV1, ExecutionAuthorizer, ModelExecutionStore, ModelServiceSnapshotV1, Provider,
    ProviderOutcomeV1, ProviderReceiptV1,
};
use daimon_protocol::{
    CommandV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionDispositionV1, ExecutionIdV1,
    HarnessProfileIdV1, IdempotencyKeyV1, OutcomeV1, PrincipalIdV1, ReplyV1, TaskAttemptRefV1,
    ToolCapabilityIdV1,
};
use daimon_service::{Service, ServiceLimitsV1};
use std::cell::Cell;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

struct Authorizer;
impl ExecutionAuthorizer for Authorizer {
    fn authorize(
        &mut self,
        _session: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
        _now: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
        Ok(AuthorityGrantV1 {
            decision_id: [8; 16],
            expires_at: 20,
            tools: request.tools.clone(),
        })
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

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "daimon-local-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> PathBuf {
        self.0.join("execution")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
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
fn exclusive_local_checkpoint_reopens_exact_result_without_provider_redispatch() {
    let fixture = Fixture::new();
    let store_limits = daimon_checkpoint::StoreLimitsV1 {
        max_bytes: 16_384,
        max_executions: 4,
        max_context_references: 4,
        max_tools: 4,
        max_artifacts: 4,
    };
    let provider_calls = Rc::new(Cell::new(0));
    let store = daimon_local::create_new(fixture.store(), store_limits).unwrap();
    assert!(daimon_local::open_existing(fixture.store(), store_limits).is_err());
    let mut service = Service::open(
        Limits::default(),
        ServiceLimitsV1 {
            max_sessions: 4,
            max_executions: 4,
        },
        Authorizer,
        Attempts,
        FakeProvider(provider_calls.clone()),
        store,
    )
    .unwrap();
    let session = service
        .open_session(AuthenticatedSessionV1 {
            principal: [4; 16],
            authority_context: [9; 16],
        })
        .unwrap();
    let command = CommandV1::Execute {
        request: request(),
        now: 10,
    };
    let result = service.execute(session, command.clone());
    assert!(matches!(result, ReplyV1::Accepted(OutcomeV1::Executed(_))));
    assert_eq!(provider_calls.get(), 1);
    drop(service);

    let store = daimon_local::open_existing(fixture.store(), store_limits).unwrap();
    let mut reopened = Service::open(
        Limits::default(),
        ServiceLimitsV1 {
            max_sessions: 4,
            max_executions: 4,
        },
        Authorizer,
        Attempts,
        FakeProvider(provider_calls.clone()),
        store,
    )
    .unwrap();
    let session = reopened
        .open_session(AuthenticatedSessionV1 {
            principal: [4; 16],
            authority_context: [9; 16],
        })
        .unwrap();
    assert_eq!(reopened.execute(session, command), result);
    assert_eq!(provider_calls.get(), 1);
}

#[test]
fn exclusive_local_model_checkpoint_has_the_same_create_and_reopen_law() {
    let fixture = Fixture::new();
    let limits = daimon_checkpoint::model::ModelStoreLimitsV1 {
        max_bytes: 16_384,
        max_executions: 4,
        max_context_references: 4,
        max_tools: 4,
        max_model_bytes: 128,
        max_context_bytes: 1_024,
        max_messages: 8,
        max_message_bytes: 1_024,
        max_output_bytes: 1_024,
        max_proposals: 4,
        max_proposal_bytes: 1_024,
    };
    let mut store = daimon_local::create_new_model(fixture.store(), limits).unwrap();
    assert_eq!(
        store.load_model().unwrap(),
        Some(ModelServiceSnapshotV1::default())
    );
    assert!(daimon_local::open_existing_model(fixture.store(), limits).is_err());
    drop(store);
    let mut reopened = daimon_local::open_existing_model(fixture.store(), limits).unwrap();
    assert_eq!(
        reopened.load_model().unwrap(),
        Some(ModelServiceSnapshotV1::default())
    );
}

#[test]
fn exclusive_local_agent_checkpoint_has_the_same_create_and_reopen_law() {
    let fixture = Fixture::new();
    let limits = daimon_checkpoint::agent::AgentStoreLimitsV1 {
        max_bytes: 64 * 1024,
        max_sessions: 4,
        max_operations_per_session: 8,
        max_events_per_session: 16,
        max_context_references: 4,
        max_tools: 4,
        max_prompt_bytes: 4 * 1024,
        max_event_bytes: 4 * 1024,
        max_permission_options: 4,
    };
    let mut store = daimon_local::create_new_agent(fixture.store(), limits).unwrap();
    assert_eq!(
        store.load_agents().unwrap(),
        Some(AgentServiceSnapshotV1::default())
    );
    assert!(daimon_local::open_existing_agent(fixture.store(), limits).is_err());
    drop(store);
    let mut reopened = daimon_local::open_existing_agent(fixture.store(), limits).unwrap();
    assert_eq!(
        reopened.load_agents().unwrap(),
        Some(AgentServiceSnapshotV1::default())
    );
}
