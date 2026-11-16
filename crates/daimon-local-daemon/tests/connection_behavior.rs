use daimon_local_daemon::{ConnectionErrorV1, ServicePort, serve_one, serve_up_to};
use daimon_protocol::{
    CommandV1, ExecutionIdV1, ExecutionPhaseV1, OutcomeV1, ReplyV1, SessionHandleV1,
};
use daimon_wire::{LimitsV1, RequestFrameV1, decode_reply, encode_request};
use std::io::{Cursor, Read, Result as IoResult, Write};

struct Port {
    calls: usize,
}

impl ServicePort for Port {
    type Error = ();

    fn execute(&mut self, _: SessionHandleV1, command: CommandV1) -> Result<ReplyV1, ()> {
        self.calls += 1;
        let execution_id = match command {
            CommandV1::Inspect { execution_id } => execution_id,
            CommandV1::Execute { request, .. } => request.execution_id,
            CommandV1::ReadPresence { .. } => unreachable!("execution test port"),
        };
        Ok(ReplyV1::Accepted(OutcomeV1::Status {
            execution_id,
            phase: ExecutionPhaseV1::Completed,
        }))
    }
}

struct Duplex {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    fail_write: bool,
}

impl Read for Duplex {
    fn read(&mut self, bytes: &mut [u8]) -> IoResult<usize> {
        self.input.read(bytes)
    }
}

impl Write for Duplex {
    fn write(&mut self, bytes: &[u8]) -> IoResult<usize> {
        if self.fail_write {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

fn framed(session: SessionHandleV1) -> Vec<u8> {
    let request = encode_request(
        &RequestFrameV1 {
            session,
            command: CommandV1::Inspect {
                execution_id: ExecutionIdV1::new([1; 16]),
            },
        },
        LimitsV1::default(),
    )
    .unwrap();
    let mut bytes = (request.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(&request);
    bytes
}

#[test]
fn connection_binds_session_and_returns_one_bounded_reply() {
    let session = SessionHandleV1(3);
    let mut io = Duplex {
        input: Cursor::new(framed(session)),
        output: Vec::new(),
        fail_write: false,
    };
    let mut port = Port { calls: 0 };
    serve_one(&mut io, session, &mut port, LimitsV1::default()).unwrap();
    assert_eq!(port.calls, 1);
    let length = u32::from_be_bytes(io.output[..4].try_into().unwrap()) as usize;
    assert_eq!(length, io.output.len() - 4);
    assert!(matches!(
        decode_reply(&io.output[4..], LimitsV1::default()).unwrap(),
        ReplyV1::Accepted(OutcomeV1::Status {
            phase: ExecutionPhaseV1::Completed,
            ..
        })
    ));
}

#[test]
fn connection_serves_a_bounded_sequence_and_accepts_clean_eof() {
    let session = SessionHandleV1(3);
    let mut input = framed(session);
    input.extend_from_slice(&framed(session));
    let mut io = Duplex {
        input: Cursor::new(input),
        output: Vec::new(),
        fail_write: false,
    };
    let mut port = Port { calls: 0 };
    assert_eq!(
        serve_up_to(&mut io, session, &mut port, LimitsV1::default(), 8).unwrap(),
        2
    );
    assert_eq!(port.calls, 2);

    let mut limited = Duplex {
        input: Cursor::new([framed(session), framed(session)].concat()),
        output: Vec::new(),
        fail_write: false,
    };
    let mut limited_port = Port { calls: 0 };
    assert_eq!(
        serve_up_to(
            &mut limited,
            session,
            &mut limited_port,
            LimitsV1::default(),
            1,
        )
        .unwrap(),
        1
    );
    assert_eq!(limited_port.calls, 1);
}

#[test]
fn substituted_session_never_dispatches_and_lost_reply_is_outcome_unknown() {
    let mut port = Port { calls: 0 };
    let mut substituted = Duplex {
        input: Cursor::new(framed(SessionHandleV1(9))),
        output: Vec::new(),
        fail_write: false,
    };
    serve_one(
        &mut substituted,
        SessionHandleV1(3),
        &mut port,
        LimitsV1::default(),
    )
    .unwrap();
    assert_eq!(port.calls, 0);

    let mut lost = Duplex {
        input: Cursor::new(framed(SessionHandleV1(3))),
        output: Vec::new(),
        fail_write: true,
    };
    assert!(matches!(
        serve_one(
            &mut lost,
            SessionHandleV1(3),
            &mut port,
            LimitsV1::default(),
        ),
        Err(ConnectionErrorV1::OutcomeUnknown(_))
    ));
    assert_eq!(port.calls, 1);
}
