use daimon_chronos::{ChronosAttemptValidator, TaskBindingV1};
use daimon_host::{AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1};
use daimon_protocol::{
    ExecuteRequestV1, ExecutionBudgetV1, ExecutionIdV1, HarnessProfileIdV1, IdempotencyKeyV1,
    PrincipalIdV1, TaskAttemptRefV1,
};
use std::time::{Duration, SystemTime};

struct Allow;

impl chronos_service::Authorizer for Allow {
    fn allows(&mut self, _: &chronos_host::native::RequestV1) -> bool {
        true
    }
}

impl chronos_service::worker::WorkerAuthorizer for Allow {
    fn allows_worker(&mut self, _: &chronos_host::worker::WorkerRequestV1) -> bool {
        true
    }

    fn allows_worker_result(
        &mut self,
        _: &chronos_host::worker::WorkerRequestV1,
        _: &chronos_engine::CommandOutcomeV2,
    ) -> bool {
        true
    }
}

fn limits() -> chronos_protocol::Limits {
    chronos_protocol::Limits {
        max_frame_bytes: 4_096,
        max_id_bytes: 64,
        max_graph_tasks: 4,
        max_dependencies_per_task: 4,
        max_capabilities_per_task: 4,
        max_capability_bytes: 64,
        max_page_entries: 4,
    }
}

fn request() -> ExecuteRequestV1 {
    ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new([1; 16]),
        task_attempt: TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 0,
            attempt_number: 1,
        },
        principal: PrincipalIdV1::new([4; 16]),
        profile: HarnessProfileIdV1::new([5; 16]),
        idempotency_key: IdempotencyKeyV1::new([6; 16]),
        context: vec![],
        tools: vec![],
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: 1,
            max_input_tokens: 1,
            max_output_tokens: 1,
            max_tool_calls: 1,
            max_context_bytes: 1,
            max_output_bytes: 1,
        },
    }
}

fn session() -> AuthenticatedSessionV1 {
    AuthenticatedSessionV1 {
        principal: [4; 16],
        authority_context: [9; 16],
    }
}

#[test]
fn real_chronos_service_running_attempt_is_validated_through_public_client() {
    use chronos_engine::{Agent, CommandOutcomeV2, Engine, TaskSpecV2};
    use chronos_host::{native::RequestV1, native::ResponseV1, worker::WorkerRequestV1};

    let mut service = chronos_service::Service::new(
        Engine::new(),
        Allow,
        chronos_service::Limits {
            max_graph_tasks: 4,
            max_page_entries: 4,
        },
    );
    let Ok(ResponseV1::Revision(revision)) = service.dispatch(RequestV1::Revision) else {
        panic!("revision expected")
    };
    assert!(matches!(
        service.dispatch(RequestV1::SubmitGraph {
            expected: revision,
            tasks: vec![TaskSpecV2::new("moira-task")],
        }),
        Ok(ResponseV1::SubmitGraph(Ok(())))
    ));
    let Ok(CommandOutcomeV2::AdvanceTime(Ok(time))) =
        service.dispatch_worker(WorkerRequestV1::AdvanceTime {
            now: SystemTime::UNIX_EPOCH,
        })
    else {
        panic!("time expected")
    };
    let Ok(CommandOutcomeV2::IssueGrant(Ok(grant))) =
        service.dispatch_worker(WorkerRequestV1::IssueGrant {
            agent: Agent::new("daimon-worker"),
            time: time.clone(),
            validity_duration: Duration::from_secs(60),
            claim_budget: Some(1),
        })
    else {
        panic!("grant expected")
    };
    let Ok(ResponseV1::Revision(revision)) = service.dispatch(RequestV1::Revision) else {
        panic!("revision expected")
    };
    assert!(matches!(
        service.dispatch_worker(WorkerRequestV1::ClaimTask {
            expected: revision,
            grant,
            task_id: "moira-task".into(),
            time,
            lease_duration: Duration::from_secs(10),
        }),
        Ok(CommandOutcomeV2::ClaimTask(Ok(_)))
    ));

    let client = chronos_adapter_native::EmbeddedClient::new(service, limits());
    let mut validator = ChronosAttemptValidator::new(
        client,
        limits(),
        1,
        vec![TaskBindingV1 {
            external_task_key: [2; 16],
            chronos_task_id: "moira-task".to_owned(),
        }],
    )
    .unwrap();
    let mut exact = request();
    assert_eq!(validator.validate(&session(), &exact), Ok(()));

    exact.task_attempt.attempt_number = 2;
    assert_eq!(
        validator.validate(&session(), &exact),
        Err(AttemptRefusalV1::NotCurrent)
    );
}
