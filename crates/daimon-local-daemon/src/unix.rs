//! Private Unix listener and transport-neutral Daimon client port.

use crate::{
    AgentConnectionErrorV1, AgentServicePort, ConnectionErrorV1, ModelServicePort, ServicePort,
    serve_agent_up_to, serve_model_up_to, serve_up_to,
};
use daimon_host::presence::{Disclosure, Observation, ReadError, Roster};
use daimon_host::{
    AttemptValidator, AuthenticatedSessionV1, ExecutionAuthorizer, ExecutionStore, Provider,
};
use daimon_protocol::agent::AgentRefusalV1;
use daimon_protocol::{CommandV1, OutcomeV1, PresenceEntryV1, RefusalV1, ReplyV1, SessionHandleV1};
use daimon_service::Service;
use daimon_wire::agent::AgentWireLimitsV1;
use daimon_wire::{LimitsV1, ModelLimitsV1, encode_session_opened};
use std::{
    convert::Infallible,
    fs,
    io::{self, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub trait Authenticator {
    type Error;
    fn authenticate(&mut self, stream: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error>;
}

pub trait ModelSessionPort: ModelServicePort<Error = Infallible> {
    fn open_model_session(
        &mut self,
        facts: AuthenticatedSessionV1,
    ) -> Result<SessionHandleV1, RefusalV1>;

    fn close_model_session(&mut self, session: SessionHandleV1) -> bool;
}

pub trait AgentSessionPort: AgentServicePort<Error = Infallible> {
    fn open_agent_service_session(
        &mut self,
        facts: AuthenticatedSessionV1,
    ) -> Result<SessionHandleV1, AgentRefusalV1>;

    fn close_agent_service_session(&mut self, session: SessionHandleV1) -> bool;
}

impl<A, T, R, C, P, S> ModelSessionPort for daimon_service::model::ModelService<A, T, R, C, P, S>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    R: daimon_host::ProviderProfileResolver,
    C: daimon_host::ContextAssembler,
    P: daimon_host::ModelProvider,
    S: daimon_host::ModelExecutionStore,
{
    fn open_model_session(
        &mut self,
        facts: AuthenticatedSessionV1,
    ) -> Result<SessionHandleV1, RefusalV1> {
        self.open_session(facts)
    }

    fn close_model_session(&mut self, session: SessionHandleV1) -> bool {
        self.close_session(session)
    }
}

impl<A, T, R, C, P, S> AgentSessionPort for daimon_service::agent::AgentService<A, T, R, C, P, S>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    R: daimon_host::agent::AgentProfileResolver,
    C: daimon_host::agent::AgentContextAssembler,
    P: daimon_host::agent::AgentProvider,
    S: daimon_host::agent::AgentSessionStore,
{
    fn open_agent_service_session(
        &mut self,
        facts: AuthenticatedSessionV1,
    ) -> Result<SessionHandleV1, AgentRefusalV1> {
        self.open_service_session(facts)
    }

    fn close_agent_service_session(&mut self, session: SessionHandleV1) -> bool {
        self.close_service_session(session)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HealthV1 {
    pub ready: bool,
    pub active_connections: u64,
    pub accepted_connections: u64,
    pub refused_connections: u64,
    pub outcome_unknown: u64,
    pub saturated: bool,
}

#[derive(Debug)]
pub enum DaemonErrorV1<A> {
    Io(io::Error),
    Authentication(A),
    Session(RefusalV1),
    Connection(ConnectionErrorV1<Infallible>),
}

#[derive(Debug)]
pub enum AgentDaemonErrorV1<A> {
    Io(io::Error),
    Authentication(A),
    Session(AgentRefusalV1),
    Connection(AgentConnectionErrorV1<Infallible>),
}

type PresenceRead = Box<dyn FnMut(&AuthenticatedSessionV1, u8) -> ReplyV1 + Send>;

struct ConnectionPort<'a, P> {
    execution: &'a mut P,
    presence: &'a mut Option<PresenceRead>,
    facts: &'a AuthenticatedSessionV1,
}

impl<P: ServicePort> ServicePort for ConnectionPort<'_, P> {
    type Error = P::Error;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        if let CommandV1::ReadPresence { limit } = command {
            return Ok(self
                .presence
                .as_mut()
                .map_or(ReplyV1::Refused(RefusalV1::PresenceUnavailable), |read| {
                    read(self.facts, limit)
                }));
        }
        self.execution.execute(session, command)
    }
}

pub struct Daemon<A, T, P, S, H>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    P: Provider,
    S: ExecutionStore,
    H: Authenticator,
{
    listener: UnixListener,
    socket_path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    service: Service<A, T, P, S>,
    authenticator: H,
    wire_limits: LimitsV1,
    io_timeout: Duration,
    max_requests_per_connection: usize,
    health: HealthV1,
    presence: Option<PresenceRead>,
}

impl<A, T, P, S, H> Daemon<A, T, P, S, H>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    P: Provider,
    S: ExecutionStore,
    H: Authenticator,
{
    pub fn bind_new(
        socket_path: impl AsRef<Path>,
        service: Service<A, T, P, S>,
        authenticator: H,
        wire_limits: LimitsV1,
        io_timeout: Duration,
        max_requests_per_connection: usize,
    ) -> io::Result<Self> {
        if io_timeout.is_zero() || max_requests_per_connection == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid daemon limits",
            ));
        }
        let socket_path = socket_path.as_ref().to_path_buf();
        if fs::symlink_metadata(&socket_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "socket path already exists",
            ));
        }
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket_path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::other("bound path is not a socket"));
        }
        Ok(Self {
            listener,
            socket_path,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
            service,
            authenticator,
            wire_limits,
            io_timeout,
            max_requests_per_connection,
            presence: None,
            health: HealthV1 {
                ready: true,
                ..HealthV1::default()
            },
        })
    }

    /// Bind the supervisor's live roster and current per-session disclosure policy.
    pub fn bind_presence(
        &mut self,
        roster: std::sync::Arc<std::sync::RwLock<Roster>>,
        mut disclosure: impl Disclosure + Send + 'static,
    ) {
        self.presence = Some(Box::new(move |facts, limit| {
            let Ok(roster) = roster.read() else {
                return ReplyV1::Refused(RefusalV1::PresenceUnavailable);
            };
            presence_reply(&roster, facts, &mut disclosure, limit)
        }));
    }

    /// Use a bounded, nonblocking census of the host's owned child processes.
    pub fn bind_local_supervisor(
        &mut self,
        supervisor: std::sync::Arc<std::sync::Mutex<crate::supervisor::LocalSupervisor>>,
        capacity: usize,
        freshness: Duration,
        mut disclosure: impl Disclosure + Send + 'static,
    ) {
        let mut roster = Roster::new(capacity, freshness);
        self.presence = Some(Box::new(move |facts, limit| {
            if !disclosure.allows_roster(facts) {
                return ReplyV1::Refused(RefusalV1::AuthorityDenied);
            }
            let Ok(mut supervisor) = supervisor.try_lock() else {
                return ReplyV1::Refused(RefusalV1::PresenceUnavailable);
            };
            if supervisor.refresh(&mut roster).is_err() {
                return ReplyV1::Refused(RefusalV1::PresenceUnavailable);
            }
            drop(supervisor);
            presence_reply(&roster, facts, &mut disclosure, limit)
        }));
    }

    pub fn health(&self) -> HealthV1 {
        self.health
    }

    pub fn serve_next(&mut self) -> Result<(), DaemonErrorV1<H::Error>> {
        let (mut stream, _) = self.listener.accept().map_err(DaemonErrorV1::Io)?;
        increment(
            &mut self.health.active_connections,
            &mut self.health.saturated,
        );
        let result = self.serve_stream(&mut stream);
        self.health.active_connections = self.health.active_connections.saturating_sub(1);
        if result.is_err() {
            increment(
                &mut self.health.refused_connections,
                &mut self.health.saturated,
            );
        }
        if matches!(
            &result,
            Err(DaemonErrorV1::Connection(
                ConnectionErrorV1::OutcomeUnknown(_)
            ))
        ) {
            increment(&mut self.health.outcome_unknown, &mut self.health.saturated);
        }
        result
    }

    fn serve_stream(&mut self, stream: &mut UnixStream) -> Result<(), DaemonErrorV1<H::Error>> {
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(DaemonErrorV1::Io)?;
        let facts = self
            .authenticator
            .authenticate(stream)
            .map_err(DaemonErrorV1::Authentication)?;
        let session = self
            .service
            .open_session(facts.clone())
            .map_err(DaemonErrorV1::Session)?;
        let result = (|| {
            write_handshake(stream, session, self.wire_limits).map_err(DaemonErrorV1::Io)?;
            serve_up_to(
                stream,
                session,
                &mut ConnectionPort {
                    execution: &mut self.service,
                    presence: &mut self.presence,
                    facts: &facts,
                },
                self.wire_limits,
                self.max_requests_per_connection,
            )
            .map(|_| ())
            .map_err(DaemonErrorV1::Connection)
        })();
        self.service.close_session(session);
        if result.is_ok() {
            increment(
                &mut self.health.accepted_connections,
                &mut self.health.saturated,
            );
        }
        result
    }
}

impl<A, T, P, S, H> Drop for Daemon<A, T, P, S, H>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    P: Provider,
    S: ExecutionStore,
    H: Authenticator,
{
    fn drop(&mut self) {
        self.health.ready = false;
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.socket_device
            && metadata.ino() == self.socket_inode
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

/// Dedicated local model endpoint. A separate socket makes protocol selection
/// explicit while retaining the same authenticated-session boundary.
pub struct ModelDaemon<M, H>
where
    M: ModelSessionPort,
    H: Authenticator,
{
    listener: UnixListener,
    socket_path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    service: M,
    authenticator: H,
    handshake_limits: LimitsV1,
    wire_limits: ModelLimitsV1,
    io_timeout: Duration,
    max_requests_per_connection: usize,
    health: HealthV1,
}

impl<M, H> ModelDaemon<M, H>
where
    M: ModelSessionPort,
    H: Authenticator,
{
    #[allow(clippy::too_many_arguments)]
    pub fn bind_new(
        socket_path: impl AsRef<Path>,
        service: M,
        authenticator: H,
        handshake_limits: LimitsV1,
        wire_limits: ModelLimitsV1,
        io_timeout: Duration,
        max_requests_per_connection: usize,
    ) -> io::Result<Self> {
        if io_timeout.is_zero() || max_requests_per_connection == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid model daemon limits",
            ));
        }
        let socket_path = socket_path.as_ref().to_path_buf();
        if fs::symlink_metadata(&socket_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "socket path already exists",
            ));
        }
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket_path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::other("bound path is not a socket"));
        }
        Ok(Self {
            listener,
            socket_path,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
            service,
            authenticator,
            handshake_limits,
            wire_limits,
            io_timeout,
            max_requests_per_connection,
            health: HealthV1 {
                ready: true,
                ..HealthV1::default()
            },
        })
    }

    pub fn health(&self) -> HealthV1 {
        self.health
    }

    pub fn serve_next(&mut self) -> Result<(), DaemonErrorV1<H::Error>> {
        let (mut stream, _) = self.listener.accept().map_err(DaemonErrorV1::Io)?;
        increment(
            &mut self.health.active_connections,
            &mut self.health.saturated,
        );
        let result = self.serve_stream(&mut stream);
        self.health.active_connections = self.health.active_connections.saturating_sub(1);
        if result.is_err() {
            increment(
                &mut self.health.refused_connections,
                &mut self.health.saturated,
            );
        }
        if matches!(
            &result,
            Err(DaemonErrorV1::Connection(
                ConnectionErrorV1::OutcomeUnknown(_)
            ))
        ) {
            increment(&mut self.health.outcome_unknown, &mut self.health.saturated);
        }
        result
    }

    fn serve_stream(&mut self, stream: &mut UnixStream) -> Result<(), DaemonErrorV1<H::Error>> {
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(DaemonErrorV1::Io)?;
        let facts = self
            .authenticator
            .authenticate(stream)
            .map_err(DaemonErrorV1::Authentication)?;
        let session = self
            .service
            .open_model_session(facts)
            .map_err(DaemonErrorV1::Session)?;
        let result = (|| {
            write_handshake(stream, session, self.handshake_limits).map_err(DaemonErrorV1::Io)?;
            serve_model_up_to(
                stream,
                session,
                &mut self.service,
                self.wire_limits,
                self.max_requests_per_connection,
            )
            .map(|_| ())
            .map_err(DaemonErrorV1::Connection)
        })();
        self.service.close_model_session(session);
        if result.is_ok() {
            increment(
                &mut self.health.accepted_connections,
                &mut self.health.saturated,
            );
        }
        result
    }
}

impl<M, H> Drop for ModelDaemon<M, H>
where
    M: ModelSessionPort,
    H: Authenticator,
{
    fn drop(&mut self) {
        self.health.ready = false;
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.socket_device
            && metadata.ino() == self.socket_inode
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

/// Dedicated local interactive-agent endpoint. The distinct socket prevents
/// canonical agent frames from being confused with legacy or model frames.
pub struct AgentDaemon<M, H>
where
    M: AgentSessionPort,
    H: Authenticator,
{
    listener: UnixListener,
    socket_path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    service: M,
    authenticator: H,
    handshake_limits: LimitsV1,
    wire_limits: AgentWireLimitsV1,
    io_timeout: Duration,
    max_requests_per_connection: usize,
    health: HealthV1,
}

impl<M, H> AgentDaemon<M, H>
where
    M: AgentSessionPort,
    H: Authenticator,
{
    #[allow(clippy::too_many_arguments)]
    pub fn bind_new(
        socket_path: impl AsRef<Path>,
        service: M,
        authenticator: H,
        handshake_limits: LimitsV1,
        wire_limits: AgentWireLimitsV1,
        io_timeout: Duration,
        max_requests_per_connection: usize,
    ) -> io::Result<Self> {
        if io_timeout.is_zero() || max_requests_per_connection == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid agent daemon limits",
            ));
        }
        let socket_path = socket_path.as_ref().to_path_buf();
        if fs::symlink_metadata(&socket_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "socket path already exists",
            ));
        }
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket_path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::other("bound path is not a socket"));
        }
        Ok(Self {
            listener,
            socket_path,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
            service,
            authenticator,
            handshake_limits,
            wire_limits,
            io_timeout,
            max_requests_per_connection,
            health: HealthV1 {
                ready: true,
                ..HealthV1::default()
            },
        })
    }

    pub fn health(&self) -> HealthV1 {
        self.health
    }

    pub fn serve_next(&mut self) -> Result<(), AgentDaemonErrorV1<H::Error>> {
        let (mut stream, _) = self.listener.accept().map_err(AgentDaemonErrorV1::Io)?;
        increment(
            &mut self.health.active_connections,
            &mut self.health.saturated,
        );
        let result = self.serve_stream(&mut stream);
        self.health.active_connections = self.health.active_connections.saturating_sub(1);
        if result.is_err() {
            increment(
                &mut self.health.refused_connections,
                &mut self.health.saturated,
            );
        }
        if matches!(
            &result,
            Err(AgentDaemonErrorV1::Connection(
                AgentConnectionErrorV1::OutcomeUnknown(_)
            ))
        ) {
            increment(&mut self.health.outcome_unknown, &mut self.health.saturated);
        }
        result
    }

    fn serve_stream(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<(), AgentDaemonErrorV1<H::Error>> {
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(AgentDaemonErrorV1::Io)?;
        let facts = self
            .authenticator
            .authenticate(stream)
            .map_err(AgentDaemonErrorV1::Authentication)?;
        let session = self
            .service
            .open_agent_service_session(facts)
            .map_err(AgentDaemonErrorV1::Session)?;
        let result = (|| {
            write_handshake(stream, session, self.handshake_limits)
                .map_err(AgentDaemonErrorV1::Io)?;
            serve_agent_up_to(
                stream,
                session,
                &mut self.service,
                self.wire_limits,
                self.max_requests_per_connection,
            )
            .map(|_| ())
            .map_err(AgentDaemonErrorV1::Connection)
        })();
        self.service.close_agent_service_session(session);
        if result.is_ok() {
            increment(
                &mut self.health.accepted_connections,
                &mut self.health.saturated,
            );
        }
        result
    }
}

impl<M, H> Drop for AgentDaemon<M, H>
where
    M: AgentSessionPort,
    H: Authenticator,
{
    fn drop(&mut self) {
        self.health.ready = false;
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.socket_device
            && metadata.ino() == self.socket_inode
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

fn presence_reply(
    roster: &Roster,
    facts: &AuthenticatedSessionV1,
    disclosure: &mut impl Disclosure,
    limit: u8,
) -> ReplyV1 {
    match roster.read(facts, disclosure, Instant::now(), usize::from(limit)) {
        Ok(page) => ReplyV1::Accepted(OutcomeV1::Presence {
            entries: page
                .entries
                .into_iter()
                .map(|entry| {
                    let (age, stale) = match entry.observation {
                        Observation::Observed { age } => (age, false),
                        Observation::Stale { age } => (age, true),
                    };
                    PresenceEntryV1 {
                        agent: entry.agent,
                        age_millis: u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
                        stale,
                    }
                })
                .collect(),
            truncated: page.truncated,
        }),
        Err(ReadError::Denied) => ReplyV1::Refused(RefusalV1::AuthorityDenied),
        Err(ReadError::Unavailable) => ReplyV1::Refused(RefusalV1::PresenceUnavailable),
        Err(ReadError::InvalidLimit) => ReplyV1::Refused(RefusalV1::InvalidInput),
    }
}

fn write_handshake(
    stream: &mut UnixStream,
    session: SessionHandleV1,
    limits: LimitsV1,
) -> io::Result<()> {
    let bytes = encode_session_opened(session, limits)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "session frame"))?;
    write_frame(stream, &bytes)
}

pub use daimon_client::unix::{
    AgentClientErrorV1, AgentUnixPort, ClientErrorV1, ModelUnixPort, UnixPort, connect,
    connect_agent, connect_model,
};

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()
}

fn increment(value: &mut u64, saturated: &mut bool) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *saturated = true;
    }
}
