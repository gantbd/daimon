use chronos_client::WireClientV1;
use chronos_protocol as chronos;
use daimon_chronos::{ChronosAttemptValidator, ConfigurationErrorV1, TaskBindingV1};
use daimon_host::{AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1};
use daimon_protocol::{
    ExecuteRequestV1, ExecutionBudgetV1, ExecutionIdV1, HarnessProfileIdV1, IdempotencyKeyV1,
    PrincipalIdV1, TaskAttemptRefV1,
};

#[derive(Clone, Copy)]
enum PortMode {
    Exact,
    Ready,
    WrongAttempt,
    WrongIncarnation,
    Malformed,
    Unavailable,
}

struct Port {
    mode: PortMode,
    calls: usize,
}

impl WireClientV1 for Port {
    type Error = ();

    fn request(&mut self, request: chronos::Request) -> Result<chronos::Response, Self::Error> {
        self.calls += 1;
        if matches!(self.mode, PortMode::Unavailable) {
            return Err(());
        }
        let chronos::Command::Snapshot { task } = request.command else {
            panic!("snapshot expected")
        };
        let (phase, attempt_number, incarnation) = match self.mode {
            PortMode::Exact | PortMode::Malformed => (chronos::Phase::Running, Some(3), "7"),
            PortMode::Ready => (chronos::Phase::Ready, None, "7"),
            PortMode::WrongAttempt => (chronos::Phase::Running, Some(4), "7"),
            PortMode::WrongIncarnation => (chronos::Phase::Running, Some(3), "8"),
            PortMode::Unavailable => unreachable!(),
        };
        Ok(chronos::Response {
            version: if matches!(self.mode, PortMode::Malformed) {
                2
            } else {
                1
            },
            outcome: chronos::Outcome::Snapshot {
                value: Some(chronos::Entry {
                    reference: chronos::Reference {
                        task,
                        incarnation: incarnation.to_owned(),
                    },
                    snapshot: chronos::Snapshot {
                        phase,
                        attempt_number,
                        dependency_count: 0,
                        required_capability_count: 1,
                        priority: 0,
                        max_attempts: 4,
                    },
                }),
                revision: Some(chronos::Revision::Finite("9".to_owned())),
            },
        })
    }
}

fn limits() -> chronos::Limits {
    chronos::Limits {
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
            task_incarnation: 7,
            attempt_number: 3,
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

fn validator(mode: PortMode) -> ChronosAttemptValidator<Port> {
    ChronosAttemptValidator::new(
        Port { mode, calls: 0 },
        limits(),
        4,
        vec![TaskBindingV1 {
            external_task_key: [2; 16],
            chronos_task_id: "moira-task".to_owned(),
        }],
    )
    .unwrap()
}

fn session() -> AuthenticatedSessionV1 {
    AuthenticatedSessionV1 {
        principal: [4; 16],
        authority_context: [9; 16],
    }
}

#[test]
fn exact_running_chronos_attempt_is_current() {
    let mut validator = validator(PortMode::Exact);
    assert_eq!(validator.validate(&session(), &request()), Ok(()));
    assert_eq!(validator.into_port().calls, 1);
}

#[test]
fn phase_attempt_incarnation_and_registry_mismatches_are_not_current() {
    for mode in [
        PortMode::Ready,
        PortMode::WrongAttempt,
        PortMode::WrongIncarnation,
    ] {
        assert_eq!(
            validator(mode).validate(&session(), &request()),
            Err(AttemptRefusalV1::NotCurrent)
        );
    }
    let mut unknown = request();
    unknown.task_attempt.task_key = [0xff; 16];
    let mut validator = validator(PortMode::Exact);
    assert_eq!(
        validator.validate(&session(), &unknown),
        Err(AttemptRefusalV1::NotCurrent)
    );
    assert_eq!(validator.into_port().calls, 0);
}

#[test]
fn transport_or_invalid_chronos_evidence_is_unavailable() {
    for mode in [PortMode::Malformed, PortMode::Unavailable] {
        assert_eq!(
            validator(mode).validate(&session(), &request()),
            Err(AttemptRefusalV1::Unavailable)
        );
    }
}

#[test]
fn bounded_registry_refuses_aliases_and_invalid_configuration() {
    let binding = TaskBindingV1 {
        external_task_key: [2; 16],
        chronos_task_id: "moira-task".to_owned(),
    };
    let port = || Port {
        mode: PortMode::Exact,
        calls: 0,
    };
    assert!(matches!(
        ChronosAttemptValidator::new(port(), limits(), 0, vec![binding.clone()]),
        Err(ConfigurationErrorV1::InvalidLimits)
    ));
    assert!(matches!(
        ChronosAttemptValidator::new(port(), limits(), 1, vec![]),
        Err(ConfigurationErrorV1::EmptyRegistry)
    ));
    assert!(matches!(
        ChronosAttemptValidator::new(port(), limits(), 1, vec![binding.clone(), binding.clone()]),
        Err(ConfigurationErrorV1::RegistryLimit)
    ));
    assert!(matches!(
        ChronosAttemptValidator::new(
            port(),
            limits(),
            2,
            vec![
                binding.clone(),
                TaskBindingV1 {
                    external_task_key: binding.external_task_key,
                    chronos_task_id: "other".to_owned(),
                },
            ],
        ),
        Err(ConfigurationErrorV1::DuplicateExternalKey)
    ));
    assert!(matches!(
        ChronosAttemptValidator::new(
            port(),
            limits(),
            2,
            vec![
                binding,
                TaskBindingV1 {
                    external_task_key: [3; 16],
                    chronos_task_id: "moira-task".to_owned(),
                },
            ],
        ),
        Err(ConfigurationErrorV1::DuplicateTaskId)
    ));
}
