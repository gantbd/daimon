//! Bounded local connection boundary for Daimon.

#![forbid(unsafe_code)]

use daimon_protocol::agent::{AgentCommandV1, AgentRefusalV1, AgentReplyV1};
use daimon_protocol::{ModelReplyV1, RefusalV1, ReplyV1, SessionHandleV1};
use daimon_wire::agent::{
    AgentWireCodecErrorV1, AgentWireLimitsV1, decode_agent_request, encode_agent_reply,
};
use daimon_wire::{
    CodecErrorV1, LimitsV1, ModelLimitsV1, decode_model_request, decode_request,
    encode_model_reply, encode_reply,
};
use std::io::{self, Read, Write};

#[cfg(unix)]
pub mod supervisor;
#[cfg(unix)]
pub mod unix;

pub trait ServicePort {
    type Error;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: daimon_protocol::CommandV1,
    ) -> Result<ReplyV1, Self::Error>;
}

pub trait ModelServicePort {
    type Error;

    fn execute_model(
        &mut self,
        session: SessionHandleV1,
        command: daimon_protocol::ModelCommandV1,
    ) -> Result<ModelReplyV1, Self::Error>;
}

pub trait AgentServicePort {
    type Error;

    fn execute_agent(
        &mut self,
        session: SessionHandleV1,
        command: AgentCommandV1,
    ) -> Result<AgentReplyV1, Self::Error>;
}

impl<A, T, P, S> ServicePort for daimon_service::Service<A, T, P, S>
where
    A: daimon_host::ExecutionAuthorizer,
    T: daimon_host::AttemptValidator,
    P: daimon_host::Provider,
    S: daimon_host::ExecutionStore,
{
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: daimon_protocol::CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        Ok(daimon_service::Service::execute(self, session, command))
    }
}

impl<A, T, R, C, P, S> ModelServicePort for daimon_service::model::ModelService<A, T, R, C, P, S>
where
    A: daimon_host::ExecutionAuthorizer,
    T: daimon_host::AttemptValidator,
    R: daimon_host::ProviderProfileResolver,
    C: daimon_host::ContextAssembler,
    P: daimon_host::ModelProvider,
    S: daimon_host::ModelExecutionStore,
{
    type Error = std::convert::Infallible;

    fn execute_model(
        &mut self,
        session: SessionHandleV1,
        command: daimon_protocol::ModelCommandV1,
    ) -> Result<ModelReplyV1, Self::Error> {
        Ok(daimon_service::model::ModelService::execute(
            self, session, command,
        ))
    }
}

impl<A, T, R, C, P, S> AgentServicePort for daimon_service::agent::AgentService<A, T, R, C, P, S>
where
    A: daimon_host::ExecutionAuthorizer,
    T: daimon_host::AttemptValidator,
    R: daimon_host::agent::AgentProfileResolver,
    C: daimon_host::agent::AgentContextAssembler,
    P: daimon_host::agent::AgentProvider,
    S: daimon_host::agent::AgentSessionStore,
{
    type Error = std::convert::Infallible;

    fn execute_agent(
        &mut self,
        session: SessionHandleV1,
        command: AgentCommandV1,
    ) -> Result<AgentReplyV1, Self::Error> {
        Ok(daimon_service::agent::AgentService::execute(
            self, session, command,
        ))
    }
}

#[derive(Debug)]
pub enum ConnectionErrorV1<E> {
    BeforeDispatch(io::Error),
    Wire(CodecErrorV1),
    Service(E),
    OutcomeUnknown(io::Error),
}

#[derive(Debug)]
pub enum AgentConnectionErrorV1<E> {
    BeforeDispatch(io::Error),
    Wire(AgentWireCodecErrorV1),
    Service(E),
    OutcomeUnknown(io::Error),
}

pub fn serve_one<IO: Read + Write, P: ServicePort>(
    io: &mut IO,
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: LimitsV1,
) -> Result<(), ConnectionErrorV1<P::Error>> {
    let mut header = [0_u8; 4];
    io.read_exact(&mut header)
        .map_err(ConnectionErrorV1::BeforeDispatch)?;
    serve_frame(io, header, connection_session, service, limits)
}

pub fn serve_up_to<IO: Read + Write, P: ServicePort>(
    io: &mut IO,
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: LimitsV1,
    max_requests: usize,
) -> Result<usize, ConnectionErrorV1<P::Error>> {
    if max_requests == 0 {
        return Err(ConnectionErrorV1::Wire(CodecErrorV1::Limit));
    }
    let mut served = 0;
    while served < max_requests {
        let mut header = [0_u8; 4];
        match io.read(&mut header[..1]) {
            Ok(0) => break,
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) => return Err(ConnectionErrorV1::BeforeDispatch(error)),
        }
        io.read_exact(&mut header[1..])
            .map_err(ConnectionErrorV1::BeforeDispatch)?;
        serve_frame(io, header, connection_session, service, limits)?;
        served += 1;
    }
    Ok(served)
}

pub fn serve_model_one<IO: Read + Write, P: ModelServicePort>(
    io: &mut IO,
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: ModelLimitsV1,
) -> Result<(), ConnectionErrorV1<P::Error>> {
    let mut header = [0_u8; 4];
    io.read_exact(&mut header)
        .map_err(ConnectionErrorV1::BeforeDispatch)?;
    serve_model_frame(io, header, connection_session, service, limits)
}

pub fn serve_model_up_to<IO: Read + Write, P: ModelServicePort>(
    io: &mut IO,
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: ModelLimitsV1,
    max_requests: usize,
) -> Result<usize, ConnectionErrorV1<P::Error>> {
    if max_requests == 0 {
        return Err(ConnectionErrorV1::Wire(CodecErrorV1::Limit));
    }
    let mut served = 0;
    while served < max_requests {
        let mut header = [0_u8; 4];
        match io.read(&mut header[..1]) {
            Ok(0) => break,
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) => return Err(ConnectionErrorV1::BeforeDispatch(error)),
        }
        io.read_exact(&mut header[1..])
            .map_err(ConnectionErrorV1::BeforeDispatch)?;
        serve_model_frame(io, header, connection_session, service, limits)?;
        served += 1;
    }
    Ok(served)
}

pub fn serve_agent_one<IO: Read + Write, P: AgentServicePort>(
    io: &mut IO,
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: AgentWireLimitsV1,
) -> Result<(), AgentConnectionErrorV1<P::Error>> {
    let mut header = [0_u8; 4];
    io.read_exact(&mut header)
        .map_err(AgentConnectionErrorV1::BeforeDispatch)?;
    serve_agent_frame(io, header, connection_session, service, limits)
}

pub fn serve_agent_up_to<IO: Read + Write, P: AgentServicePort>(
    io: &mut IO,
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: AgentWireLimitsV1,
    max_requests: usize,
) -> Result<usize, AgentConnectionErrorV1<P::Error>> {
    if max_requests == 0 {
        return Err(AgentConnectionErrorV1::Wire(AgentWireCodecErrorV1::Limit));
    }
    let mut served = 0;
    while served < max_requests {
        let mut header = [0_u8; 4];
        match io.read(&mut header[..1]) {
            Ok(0) => break,
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) => return Err(AgentConnectionErrorV1::BeforeDispatch(error)),
        }
        io.read_exact(&mut header[1..])
            .map_err(AgentConnectionErrorV1::BeforeDispatch)?;
        serve_agent_frame(io, header, connection_session, service, limits)?;
        served += 1;
    }
    Ok(served)
}

fn serve_frame<IO: Read + Write, P: ServicePort>(
    io: &mut IO,
    header: [u8; 4],
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: LimitsV1,
) -> Result<(), ConnectionErrorV1<P::Error>> {
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| ConnectionErrorV1::Wire(CodecErrorV1::Limit))?;
    if length == 0 || length > limits.max_frame_bytes {
        return Err(ConnectionErrorV1::Wire(CodecErrorV1::Limit));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ConnectionErrorV1::Wire(CodecErrorV1::Capacity))?;
    bytes.resize(length, 0);
    io.read_exact(&mut bytes)
        .map_err(ConnectionErrorV1::BeforeDispatch)?;
    let frame = decode_request(&bytes, limits).map_err(ConnectionErrorV1::Wire)?;
    let reply = if frame.session != connection_session {
        ReplyV1::Refused(RefusalV1::UnknownSession)
    } else {
        service
            .execute(connection_session, frame.command)
            .map_err(ConnectionErrorV1::Service)?
    };
    let encoded = encode_reply(&reply, limits).map_err(ConnectionErrorV1::Wire)?;
    let length =
        u32::try_from(encoded.len()).map_err(|_| ConnectionErrorV1::Wire(CodecErrorV1::Limit))?;
    io.write_all(&length.to_be_bytes())
        .and_then(|()| io.write_all(&encoded))
        .and_then(|()| io.flush())
        .map_err(ConnectionErrorV1::OutcomeUnknown)
}

fn serve_model_frame<IO: Read + Write, P: ModelServicePort>(
    io: &mut IO,
    header: [u8; 4],
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: ModelLimitsV1,
) -> Result<(), ConnectionErrorV1<P::Error>> {
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| ConnectionErrorV1::Wire(CodecErrorV1::Limit))?;
    if length == 0 || length > limits.max_frame_bytes {
        return Err(ConnectionErrorV1::Wire(CodecErrorV1::Limit));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ConnectionErrorV1::Wire(CodecErrorV1::Capacity))?;
    bytes.resize(length, 0);
    io.read_exact(&mut bytes)
        .map_err(ConnectionErrorV1::BeforeDispatch)?;
    let frame = decode_model_request(&bytes, limits).map_err(ConnectionErrorV1::Wire)?;
    let reply = if frame.session != connection_session {
        ModelReplyV1::Refused(RefusalV1::UnknownSession)
    } else {
        service
            .execute_model(connection_session, frame.command)
            .map_err(ConnectionErrorV1::Service)?
    };
    let encoded = encode_model_reply(&reply, limits).map_err(ConnectionErrorV1::Wire)?;
    let length =
        u32::try_from(encoded.len()).map_err(|_| ConnectionErrorV1::Wire(CodecErrorV1::Limit))?;
    io.write_all(&length.to_be_bytes())
        .and_then(|()| io.write_all(&encoded))
        .and_then(|()| io.flush())
        .map_err(ConnectionErrorV1::OutcomeUnknown)
}

fn serve_agent_frame<IO: Read + Write, P: AgentServicePort>(
    io: &mut IO,
    header: [u8; 4],
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: AgentWireLimitsV1,
) -> Result<(), AgentConnectionErrorV1<P::Error>> {
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| AgentConnectionErrorV1::Wire(AgentWireCodecErrorV1::Limit))?;
    if length == 0 || length > limits.max_frame_bytes {
        return Err(AgentConnectionErrorV1::Wire(AgentWireCodecErrorV1::Limit));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| AgentConnectionErrorV1::Wire(AgentWireCodecErrorV1::Capacity))?;
    bytes.resize(length, 0);
    io.read_exact(&mut bytes)
        .map_err(AgentConnectionErrorV1::BeforeDispatch)?;
    let frame = decode_agent_request(&bytes, limits).map_err(AgentConnectionErrorV1::Wire)?;
    let reply = if frame.service_session != connection_session {
        AgentReplyV1::Refused(AgentRefusalV1::UnknownServiceSession)
    } else {
        service
            .execute_agent(connection_session, frame.command)
            .map_err(AgentConnectionErrorV1::Service)?
    };
    let encoded = encode_agent_reply(&reply, limits).map_err(AgentConnectionErrorV1::Wire)?;
    let length = u32::try_from(encoded.len())
        .map_err(|_| AgentConnectionErrorV1::Wire(AgentWireCodecErrorV1::Limit))?;
    io.write_all(&length.to_be_bytes())
        .and_then(|()| io.write_all(&encoded))
        .and_then(|()| io.flush())
        .map_err(AgentConnectionErrorV1::OutcomeUnknown)
}
