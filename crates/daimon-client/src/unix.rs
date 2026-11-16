//! Private Unix client transport using the session authenticated by Daimon.
use daimon_protocol::agent::{AgentCommandV1, AgentReplyV1};
use daimon_protocol::{CommandV1, ModelCommandV1, ModelReplyV1, ReplyV1, SessionHandleV1};
use daimon_wire::agent::{
    AgentRequestFrameV1, AgentWireCodecErrorV1, AgentWireLimitsV1, decode_agent_reply,
    encode_agent_request,
};
use daimon_wire::{
    CodecErrorV1, LimitsV1, ModelLimitsV1, ModelRequestFrameV1, RequestFrameV1, decode_model_reply,
    decode_reply, decode_session_opened,
};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

#[derive(Debug)]
pub enum ClientErrorV1 {
    NotSent(io::Error),
    OutcomeUnknown(io::Error),
    Wire(CodecErrorV1),
    SessionMismatch,
}

#[derive(Debug)]
pub enum AgentClientErrorV1 {
    NotSent(io::Error),
    OutcomeUnknown(io::Error),
    Wire(AgentWireCodecErrorV1),
    SessionMismatch,
}

pub struct UnixPort {
    stream: UnixStream,
    session: SessionHandleV1,
    limits: LimitsV1,
}

pub struct ModelUnixPort {
    stream: UnixStream,
    session: SessionHandleV1,
    limits: ModelLimitsV1,
}

pub struct AgentUnixPort {
    stream: UnixStream,
    session: SessionHandleV1,
    limits: AgentWireLimitsV1,
}

pub fn connect(
    path: impl AsRef<Path>,
    limits: LimitsV1,
    io_timeout: Duration,
) -> Result<(SessionHandleV1, UnixPort), ClientErrorV1> {
    let stream = UnixStream::connect(path).map_err(ClientErrorV1::NotSent)?;
    stream
        .set_read_timeout(Some(io_timeout))
        .and_then(|()| stream.set_write_timeout(Some(io_timeout)))
        .map_err(ClientErrorV1::NotSent)?;
    let mut port = UnixPort {
        stream,
        session: SessionHandleV1(0),
        limits,
    };
    let bytes =
        read_frame(&mut port.stream, limits.max_frame_bytes).map_err(ClientErrorV1::NotSent)?;
    let session = decode_session_opened(&bytes, limits).map_err(ClientErrorV1::Wire)?;
    port.session = session;
    Ok((session, port))
}

pub fn connect_model(
    path: impl AsRef<Path>,
    handshake_limits: LimitsV1,
    limits: ModelLimitsV1,
    io_timeout: Duration,
) -> Result<(SessionHandleV1, ModelUnixPort), ClientErrorV1> {
    let stream = UnixStream::connect(path).map_err(ClientErrorV1::NotSent)?;
    stream
        .set_read_timeout(Some(io_timeout))
        .and_then(|()| stream.set_write_timeout(Some(io_timeout)))
        .map_err(ClientErrorV1::NotSent)?;
    let mut port = ModelUnixPort {
        stream,
        session: SessionHandleV1(0),
        limits,
    };
    let bytes = read_frame(&mut port.stream, handshake_limits.max_frame_bytes)
        .map_err(ClientErrorV1::NotSent)?;
    let session = decode_session_opened(&bytes, handshake_limits).map_err(ClientErrorV1::Wire)?;
    port.session = session;
    Ok((session, port))
}

pub fn connect_agent(
    path: impl AsRef<Path>,
    handshake_limits: LimitsV1,
    limits: AgentWireLimitsV1,
    io_timeout: Duration,
) -> Result<(SessionHandleV1, AgentUnixPort), AgentClientErrorV1> {
    let stream = UnixStream::connect(path).map_err(AgentClientErrorV1::NotSent)?;
    stream
        .set_read_timeout(Some(io_timeout))
        .and_then(|()| stream.set_write_timeout(Some(io_timeout)))
        .map_err(AgentClientErrorV1::NotSent)?;
    let mut port = AgentUnixPort {
        stream,
        session: SessionHandleV1(0),
        limits,
    };
    let bytes = read_frame(&mut port.stream, handshake_limits.max_frame_bytes)
        .map_err(AgentClientErrorV1::NotSent)?;
    let session = decode_session_opened(&bytes, handshake_limits)
        .map_err(|error| AgentClientErrorV1::Wire(map_handshake_error(error)))?;
    port.session = session;
    Ok((session, port))
}

impl crate::ServicePort for UnixPort {
    type Error = ClientErrorV1;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        if session != self.session {
            return Err(ClientErrorV1::SessionMismatch);
        }
        let request =
            daimon_wire::encode_request(&RequestFrameV1 { session, command }, self.limits)
                .map_err(ClientErrorV1::Wire)?;
        write_frame(&mut self.stream, &request).map_err(ClientErrorV1::OutcomeUnknown)?;
        let reply = read_frame(&mut self.stream, self.limits.max_frame_bytes)
            .map_err(ClientErrorV1::OutcomeUnknown)?;
        decode_reply(&reply, self.limits).map_err(ClientErrorV1::Wire)
    }
}

impl crate::ModelServicePort for ModelUnixPort {
    type Error = ClientErrorV1;

    fn execute_model(
        &mut self,
        session: SessionHandleV1,
        command: ModelCommandV1,
    ) -> Result<ModelReplyV1, Self::Error> {
        if session != self.session {
            return Err(ClientErrorV1::SessionMismatch);
        }
        let request = daimon_wire::encode_model_request(
            &ModelRequestFrameV1 { session, command },
            self.limits,
        )
        .map_err(ClientErrorV1::Wire)?;
        write_frame(&mut self.stream, &request).map_err(ClientErrorV1::OutcomeUnknown)?;
        let reply = read_frame(&mut self.stream, self.limits.max_frame_bytes)
            .map_err(ClientErrorV1::OutcomeUnknown)?;
        decode_model_reply(&reply, self.limits).map_err(ClientErrorV1::Wire)
    }
}

impl crate::AgentServicePort for AgentUnixPort {
    type Error = AgentClientErrorV1;

    fn execute_agent(
        &mut self,
        session: SessionHandleV1,
        command: AgentCommandV1,
    ) -> Result<AgentReplyV1, Self::Error> {
        if session != self.session {
            return Err(AgentClientErrorV1::SessionMismatch);
        }
        let request = encode_agent_request(
            &AgentRequestFrameV1 {
                service_session: session,
                command,
            },
            self.limits,
        )
        .map_err(AgentClientErrorV1::Wire)?;
        write_frame(&mut self.stream, &request).map_err(AgentClientErrorV1::OutcomeUnknown)?;
        let reply = read_frame(&mut self.stream, self.limits.max_frame_bytes)
            .map_err(AgentClientErrorV1::OutcomeUnknown)?;
        decode_agent_reply(&reply, self.limits).map_err(AgentClientErrorV1::Wire)
    }
}

fn map_handshake_error(error: CodecErrorV1) -> AgentWireCodecErrorV1 {
    match error {
        CodecErrorV1::Limit => AgentWireCodecErrorV1::Limit,
        CodecErrorV1::Malformed => AgentWireCodecErrorV1::Malformed,
        CodecErrorV1::Unsupported => AgentWireCodecErrorV1::Unsupported,
        CodecErrorV1::Capacity => AgentWireCodecErrorV1::Capacity,
    }
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()
}

fn read_frame(stream: &mut UnixStream, maximum: usize) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length"))?;
    if length == 0 || length > maximum {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame limit"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("frame capacity"))?;
    bytes.resize(length, 0);
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
