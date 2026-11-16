use daimon_local_daemon::{AgentConnectionErrorV1, AgentServicePort, serve_agent_one};
use daimon_protocol::AgentSessionIdV1;
use daimon_protocol::SessionHandleV1;
use daimon_protocol::agent::{AgentCommandV1, AgentRefusalV1, AgentReplyV1};
use daimon_wire::agent::{
    AgentRequestFrameV1, AgentWireLimitsV1, decode_agent_reply, encode_agent_request,
};
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
struct Port(Vec<AgentCommandV1>);

impl AgentServicePort for Port {
    type Error = Infallible;

    fn execute_agent(
        &mut self,
        _: SessionHandleV1,
        command: AgentCommandV1,
    ) -> Result<AgentReplyV1, Self::Error> {
        self.0.push(command);
        Ok(AgentReplyV1::Refused(AgentRefusalV1::Unsupported))
    }
}

fn framed(service_session: SessionHandleV1) -> Duplex {
    let input = framed_input(service_session);
    Duplex {
        input: io::Cursor::new(input),
        output: Vec::new(),
    }
}

fn framed_input(service_session: SessionHandleV1) -> Vec<u8> {
    let request = encode_agent_request(
        &AgentRequestFrameV1 {
            service_session,
            command: AgentCommandV1::Inspect {
                session: AgentSessionIdV1::new([8; 16]),
            },
        },
        AgentWireLimitsV1::default(),
    )
    .unwrap();
    let mut input = Vec::with_capacity(request.len() + 4);
    input.extend_from_slice(&u32::try_from(request.len()).unwrap().to_be_bytes());
    input.extend_from_slice(&request);
    input
}

fn reply(io: &Duplex) -> AgentReplyV1 {
    let length = usize::try_from(u32::from_be_bytes(io.output[..4].try_into().unwrap())).unwrap();
    decode_agent_reply(&io.output[4..4 + length], AgentWireLimitsV1::default()).unwrap()
}

#[test]
fn authenticated_agent_frame_dispatches_once() {
    let session = SessionHandleV1(8);
    let mut io = framed(session);
    let mut port = Port::default();
    serve_agent_one(&mut io, session, &mut port, AgentWireLimitsV1::default()).unwrap();
    assert_eq!(port.0.len(), 1);
    assert_eq!(
        reply(&io),
        AgentReplyV1::Refused(AgentRefusalV1::Unsupported)
    );
}

#[test]
fn frame_cannot_substitute_authenticated_agent_service_session() {
    let mut io = framed(SessionHandleV1(9));
    let mut port = Port::default();
    serve_agent_one(
        &mut io,
        SessionHandleV1(8),
        &mut port,
        AgentWireLimitsV1::default(),
    )
    .unwrap();
    assert!(port.0.is_empty());
    assert_eq!(
        reply(&io),
        AgentReplyV1::Refused(AgentRefusalV1::UnknownServiceSession)
    );
}

#[test]
fn lost_agent_reply_is_outcome_unknown_after_exactly_one_dispatch() {
    struct LostReply(io::Cursor<Vec<u8>>);

    impl io::Read for LostReply {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.0.read(bytes)
        }
    }

    impl io::Write for LostReply {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "lost reply"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let session = SessionHandleV1(8);
    let mut io = LostReply(io::Cursor::new(framed_input(session)));
    let mut port = Port::default();
    let error =
        serve_agent_one(&mut io, session, &mut port, AgentWireLimitsV1::default()).unwrap_err();
    assert_eq!(port.0.len(), 1);
    assert!(matches!(error, AgentConnectionErrorV1::OutcomeUnknown(_)));
}

#[cfg(unix)]
mod unix_delivery {
    use super::*;
    use daimon_client::AgentReadOnlyClient;
    use daimon_host::AuthenticatedSessionV1;
    use daimon_local_daemon::unix::{AgentDaemon, AgentSessionPort, Authenticator, connect_agent};
    use daimon_wire::LimitsV1;
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixStream},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::Duration,
    };

    struct Authentication;

    impl Authenticator for Authentication {
        type Error = Infallible;

        fn authenticate(&mut self, _: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error> {
            Ok(AuthenticatedSessionV1 {
                principal: [4; 16],
                authority_context: [9; 16],
            })
        }
    }

    #[derive(Default)]
    struct SessionPort {
        opened: bool,
    }

    impl AgentServicePort for SessionPort {
        type Error = Infallible;

        fn execute_agent(
            &mut self,
            session: SessionHandleV1,
            _: AgentCommandV1,
        ) -> Result<AgentReplyV1, Self::Error> {
            assert!(self.opened);
            assert_eq!(session, SessionHandleV1(41));
            Ok(AgentReplyV1::Refused(AgentRefusalV1::Unsupported))
        }
    }

    impl AgentSessionPort for SessionPort {
        fn open_agent_service_session(
            &mut self,
            _: AuthenticatedSessionV1,
        ) -> Result<SessionHandleV1, AgentRefusalV1> {
            assert!(!self.opened);
            self.opened = true;
            Ok(SessionHandleV1(41))
        }

        fn close_agent_service_session(&mut self, session: SessionHandleV1) -> bool {
            assert_eq!(session, SessionHandleV1(41));
            self.opened = false;
            true
        }
    }

    #[test]
    fn private_socket_authenticates_binds_and_delivers_agent_frames() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "daimon-agent-delivery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let socket = directory.join("agent.sock");
        let daemon = AgentDaemon::bind_new(
            &socket,
            SessionPort::default(),
            Authentication,
            LimitsV1::default(),
            AgentWireLimitsV1::default(),
            Duration::from_secs(2),
            1,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let server = thread::spawn(move || {
            let mut daemon = daemon;
            daemon.serve_next().unwrap();
            assert_eq!(daemon.health().accepted_connections, 1);
        });
        let (service_session, port) = connect_agent(
            &socket,
            LimitsV1::default(),
            AgentWireLimitsV1::default(),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(service_session, SessionHandleV1(41));
        let mut client = AgentReadOnlyClient::new(service_session, port);
        assert_eq!(
            client.inspect(AgentSessionIdV1::new([8; 16])).unwrap(),
            AgentReplyV1::Refused(AgentRefusalV1::Unsupported)
        );
        drop(client);
        server.join().unwrap();
        assert!(!socket.exists());
        fs::remove_dir(&directory).unwrap();
    }
}
