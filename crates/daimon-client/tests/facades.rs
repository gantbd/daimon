use daimon_client::{
    ExecutionClient, ModelExecutionClient, ModelReadOnlyClient, ModelServicePort, ReadOnlyClient,
    ServicePort,
};
use daimon_protocol::{
    CommandV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionIdV1, HarnessProfileIdV1,
    IdempotencyKeyV1, ModelCommandV1, ModelOutcomeV1, ModelReplyV1, OutcomeV1, PrincipalIdV1,
    ReplyV1, SessionHandleV1, TaskAttemptRefV1,
};

#[derive(Default)]
struct Port(Vec<(SessionHandleV1, CommandV1)>);

impl ServicePort for Port {
    type Error = ();

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        self.0.push((session, command.clone()));
        Ok(match command {
            CommandV1::ReadPresence { .. } => unreachable!("execution test port"),
            CommandV1::Execute { request, .. } => ReplyV1::Accepted(OutcomeV1::OutcomeUnknown {
                execution_id: request.execution_id,
            }),
            CommandV1::Inspect { execution_id } => ReplyV1::Accepted(OutcomeV1::Status {
                execution_id,
                phase: daimon_protocol::ExecutionPhaseV1::OutcomeUnknown,
            }),
        })
    }
}

#[derive(Default)]
struct ModelPort(Vec<(SessionHandleV1, ModelCommandV1)>);

impl ModelServicePort for ModelPort {
    type Error = ();

    fn execute_model(
        &mut self,
        session: SessionHandleV1,
        command: ModelCommandV1,
    ) -> Result<ModelReplyV1, Self::Error> {
        self.0.push((session, command.clone()));
        Ok(match command {
            ModelCommandV1::Execute { request, .. } | ModelCommandV1::Resume { request, .. } => {
                ModelReplyV1::Accepted(ModelOutcomeV1::OutcomeUnknown {
                    execution_id: request.execution_id,
                })
            }
            ModelCommandV1::Inspect { execution_id } => {
                ModelReplyV1::Accepted(ModelOutcomeV1::Status {
                    execution_id,
                    phase: daimon_protocol::ExecutionPhaseV1::OutcomeUnknown,
                })
            }
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
        idempotency_key: IdempotencyKeyV1::new([7; 16]),
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

#[test]
fn mutation_and_read_only_facades_emit_only_their_native_commands() {
    let session = SessionHandleV1(9);
    let mut execution = ExecutionClient::new(session, Port::default());
    execution.execute(request(), 10).unwrap();
    let execution_port = execution.into_port();
    assert!(matches!(
        execution_port.0.as_slice(),
        [(SessionHandleV1(9), CommandV1::Execute { .. })]
    ));

    let mut read = ReadOnlyClient::new(session, Port::default());
    read.inspect(ExecutionIdV1::new([1; 16])).unwrap();
    let read_port = read.into_port();
    assert!(matches!(
        read_port.0.as_slice(),
        [(SessionHandleV1(9), CommandV1::Inspect { .. })]
    ));
}

#[test]
fn model_facades_emit_only_the_additive_model_command_family() {
    let session = SessionHandleV1(9);
    let mut execution = ModelExecutionClient::new(session, ModelPort::default());
    execution.execute(request(), 10).unwrap();
    let execution_port = execution.into_port();
    assert!(matches!(
        execution_port.0.as_slice(),
        [(SessionHandleV1(9), ModelCommandV1::Execute { .. })]
    ));

    let mut read = ModelReadOnlyClient::new(session, ModelPort::default());
    assert_eq!(
        read.inspect_status(ExecutionIdV1::new([1; 16])),
        daimon_client::ExecutionStatusV1::Observed(
            daimon_protocol::ExecutionPhaseV1::OutcomeUnknown
        )
    );
    let read_port = read.into_port();
    assert!(matches!(
        read_port.0.as_slice(),
        [(SessionHandleV1(9), ModelCommandV1::Inspect { .. })]
    ));
}
