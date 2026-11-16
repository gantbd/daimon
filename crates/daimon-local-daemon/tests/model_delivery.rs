use daimon_local_daemon::{ModelServicePort, serve_model_one};
use daimon_protocol::{
    ContentDigestV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionIdV1, HarnessProfileIdV1,
    IdempotencyKeyV1, ModelCommandV1, ModelOutcomeV1, ModelReplyV1, PrincipalIdV1, RefusalV1,
    ResumeToolResultV1, SessionHandleV1, TaskAttemptRefV1,
};
use daimon_wire::{ModelLimitsV1, ModelRequestFrameV1, decode_model_reply, encode_model_request};
use std::{convert::Infallible, io};

struct Duplex {
    input: io::Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl io::Read for Duplex {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}

impl io::Write for Duplex {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct Port(usize);

impl ModelServicePort for Port {
    type Error = Infallible;

    fn execute_model(
        &mut self,
        _session: SessionHandleV1,
        command: ModelCommandV1,
    ) -> Result<ModelReplyV1, Self::Error> {
        self.0 += 1;
        let ModelCommandV1::Execute { request, .. } = command else {
            unreachable!()
        };
        Ok(ModelReplyV1::Accepted(ModelOutcomeV1::OutcomeUnknown {
            execution_id: request.execution_id,
        }))
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
        tools: vec![],
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: 1,
            max_input_tokens: 1,
            max_output_tokens: 1,
            max_tool_calls: 0,
            max_context_bytes: 1,
            max_output_bytes: 1,
        },
    }
}

fn framed(session: SessionHandleV1) -> Duplex {
    framed_command(
        session,
        ModelCommandV1::Execute {
            request: request(),
            now: 7,
        },
    )
}

fn framed_command(session: SessionHandleV1, command: ModelCommandV1) -> Duplex {
    let limits = ModelLimitsV1::default();
    let request = encode_model_request(&ModelRequestFrameV1 { session, command }, limits).unwrap();
    let mut input = Vec::with_capacity(request.len() + 4);
    input.extend_from_slice(&u32::try_from(request.len()).unwrap().to_be_bytes());
    input.extend_from_slice(&request);
    Duplex {
        input: io::Cursor::new(input),
        output: Vec::new(),
    }
}

#[derive(Default)]
struct ResumePort(Option<ModelCommandV1>);

impl ModelServicePort for ResumePort {
    type Error = Infallible;

    fn execute_model(
        &mut self,
        _session: SessionHandleV1,
        command: ModelCommandV1,
    ) -> Result<ModelReplyV1, Self::Error> {
        let execution_id = match &command {
            ModelCommandV1::Resume { request, .. } => request.execution_id,
            _ => unreachable!(),
        };
        self.0 = Some(command);
        Ok(ModelReplyV1::Accepted(ModelOutcomeV1::OutcomeUnknown {
            execution_id,
        }))
    }
}

fn reply(io: &Duplex) -> ModelReplyV1 {
    let length = usize::try_from(u32::from_be_bytes(io.output[..4].try_into().unwrap())).unwrap();
    decode_model_reply(&io.output[4..4 + length], ModelLimitsV1::default()).unwrap()
}

#[test]
fn authenticated_model_frame_dispatches_once() {
    let session = SessionHandleV1(8);
    let mut io = framed(session);
    let mut port = Port::default();
    serve_model_one(&mut io, session, &mut port, ModelLimitsV1::default()).unwrap();
    assert_eq!(port.0, 1);
    assert!(matches!(
        reply(&io),
        ModelReplyV1::Accepted(ModelOutcomeV1::OutcomeUnknown { .. })
    ));
}

#[test]
fn frame_session_cannot_override_authenticated_connection_session() {
    let mut io = framed(SessionHandleV1(9));
    let mut port = Port::default();
    serve_model_one(
        &mut io,
        SessionHandleV1(8),
        &mut port,
        ModelLimitsV1::default(),
    )
    .unwrap();
    assert_eq!(port.0, 0);
    assert_eq!(reply(&io), ModelReplyV1::Refused(RefusalV1::UnknownSession));
}

#[test]
fn authenticated_resume_frame_preserves_exact_tool_result() {
    let session = SessionHandleV1(8);
    let command = ModelCommandV1::Resume {
        request: request(),
        source_execution: ExecutionIdV1::new([9; 16]),
        results: vec![ResumeToolResultV1 {
            request: [10; 16],
            evidence_digest: ContentDigestV1::new([11; 32]),
            output_digest: ContentDigestV1::new([12; 32]),
            output: b"exact output".to_vec(),
        }],
        now: 7,
    };
    let mut io = framed_command(session, command.clone());
    let mut port = ResumePort::default();
    serve_model_one(&mut io, session, &mut port, ModelLimitsV1::default()).unwrap();
    assert_eq!(port.0, Some(command));
}
