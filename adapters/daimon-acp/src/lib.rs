//! Bounded ACP v1 subprocess projection for Daimon agent sessions.
//!
//! Launch material and workspace paths are host-owned registry state. Public
//! protocol values carry only opaque identities and credential-free digests.

#![forbid(unsafe_code)]

use daimon_host::agent::{
    AgentClientFileReader, AgentClientTerminal, AgentFileReadReceiptV1, AgentFileReadRefusalV1,
    AgentFileReadRequestV1, AgentProfileResolver, AgentProvider, AgentProviderInvocationV1,
    AgentProviderOutcomeV1, AgentProviderReceiptV1, AgentProviderRecoveryV1,
    AgentTerminalCreateRequestV1, AgentTerminalCreatedV1, AgentTerminalOutputV1,
    AgentTerminalRefusalV1,
};
use daimon_host::{AuthenticatedSessionV1, ProfileRefusalV1};
pub use daimon_process::ProcessIsolationV1;
use daimon_protocol::{self as protocol, agent::*};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::{Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpLimitsV1 {
    pub max_sessions: usize,
    pub max_line_bytes: usize,
    pub max_events_per_slice: usize,
    pub max_event_bytes: usize,
    pub max_context_bytes: usize,
    pub max_permission_options: usize,
    pub startup_timeout: Duration,
    pub slice_wait: Duration,
    pub cancellation_timeout: Duration,
    pub close_timeout: Duration,
}

impl Default for AcpLimitsV1 {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            max_line_bytes: 4 * 1024 * 1024,
            max_events_per_slice: 128,
            max_event_bytes: 1024 * 1024,
            max_context_bytes: 4 * 1024 * 1024,
            max_permission_options: 16,
            startup_timeout: Duration::from_secs(10),
            slice_wait: Duration::from_millis(25),
            cancellation_timeout: Duration::from_secs(5),
            close_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone)]
pub struct AcpLaunchProfileV1 {
    pub snapshot: AgentProfileSnapshotV1,
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    /// Exact environment names copied from the host. The child environment is
    /// otherwise cleared; values are never retained in protocol/checkpoint state.
    pub inherited_environment_names: Vec<OsString>,
    /// Optional bounded ACP v1 agent-handled authentication method selected by
    /// deployment configuration. Terminal methods are never invoked on the ACP
    /// connection and credential material is never carried here.
    pub agent_authentication_method: Option<String>,
    pub isolation: ProcessIsolationV1,
}

impl std::fmt::Debug for AcpLaunchProfileV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcpLaunchProfileV1")
            .field("snapshot", &self.snapshot)
            .field("program", &self.program)
            .field(
                "arguments",
                &format_args!("<{} redacted>", self.arguments.len()),
            )
            .field(
                "inherited_environment_names",
                &format_args!("<{} redacted>", self.inherited_environment_names.len()),
            )
            .field(
                "agent_authentication_method",
                &self
                    .agent_authentication_method
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("isolation", &self.isolation)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcpWorkspaceV1 {
    pub identity: [u8; 16],
    pub path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcpConfigurationErrorV1 {
    InvalidLimits,
    InvalidProfile,
    DuplicateProfile,
    InvalidWorkspace,
    DuplicateWorkspace,
}

enum ReadFrame {
    Message(Value),
    Invalid,
    Eof,
}

struct PendingPermission {
    rpc_id: Value,
    request: protocol::AgentPermissionRequestIdV1,
    options: BTreeMap<protocol::AgentPermissionOptionIdV1, Value>,
}

struct PendingTurn {
    turn: protocol::AgentTurnIdV1,
    prompt_request_id: u64,
    execution: protocol::ExecuteRequestV1,
    now: u64,
    permission: Option<PendingPermission>,
}

struct PendingTerminalWait {
    rpc_id: Value,
    terminal_id: Vec<u8>,
}

#[derive(Clone, Copy)]
struct TerminalDispatchContext {
    session: protocol::AgentSessionIdV1,
    turn: protocol::AgentTurnIdV1,
    maximum: usize,
    allow_create: bool,
}

struct AcpSession {
    child: Child,
    stdin: ChildStdin,
    frames: Receiver<ReadFrame>,
    remote_session: String,
    profile_digest: protocol::ContentDigestV1,
    capabilities: AgentCapabilitiesV1,
    close_supported: bool,
    next_request_id: u64,
    next_cursor: u64,
    pending: Option<PendingTurn>,
    open_context: Vec<protocol::ContextEvidenceV1>,
    workspace: [u8; 16],
    file_read_enabled: bool,
    terminal_enabled: bool,
    terminal_waits: Vec<PendingTerminalWait>,
}

impl Drop for AcpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct AcpProvider {
    limits: AcpLimitsV1,
    profiles: BTreeMap<protocol::ContentDigestV1, AcpLaunchProfileV1>,
    workspaces: BTreeMap<[u8; 16], PathBuf>,
    sessions: BTreeMap<protocol::AgentSessionIdV1, AcpSession>,
    file_reader: Box<dyn AgentClientFileReader>,
    terminal: Box<dyn AgentClientTerminal>,
}

impl Drop for AcpProvider {
    fn drop(&mut self) {
        for session in self.sessions.keys().copied().collect::<Vec<_>>() {
            self.terminal.release_agent_terminals(session);
        }
    }
}

struct DisabledFileReader;

struct DisabledTerminal;

impl AgentClientFileReader for DisabledFileReader {
    fn supports_agent_file_read(
        &self,
        _request: &AgentOpenRequestV1,
        _profile: &AgentProfileSnapshotV1,
    ) -> bool {
        false
    }

    fn read_agent_file(
        &mut self,
        _request: &AgentFileReadRequestV1,
    ) -> Result<AgentFileReadReceiptV1, AgentFileReadRefusalV1> {
        Err(AgentFileReadRefusalV1::Denied)
    }
}

impl AgentClientTerminal for DisabledTerminal {
    fn supports_agent_terminal(
        &self,
        _request: &AgentOpenRequestV1,
        _profile: &AgentProfileSnapshotV1,
    ) -> bool {
        false
    }

    fn create_agent_terminal(
        &mut self,
        _request: &AgentTerminalCreateRequestV1,
    ) -> Result<AgentTerminalCreatedV1, AgentTerminalRefusalV1> {
        Err(AgentTerminalRefusalV1::Denied)
    }

    fn output_agent_terminal(
        &mut self,
        _session: protocol::AgentSessionIdV1,
        _terminal_id: &[u8],
    ) -> Result<AgentTerminalOutputV1, AgentTerminalRefusalV1> {
        Err(AgentTerminalRefusalV1::Denied)
    }

    fn poll_agent_terminal_exit(
        &mut self,
        _session: protocol::AgentSessionIdV1,
        _terminal_id: &[u8],
    ) -> Result<Option<daimon_host::agent::AgentTerminalExitV1>, AgentTerminalRefusalV1> {
        Err(AgentTerminalRefusalV1::Denied)
    }

    fn kill_agent_terminal(
        &mut self,
        _session: protocol::AgentSessionIdV1,
        _terminal_id: &[u8],
    ) -> Result<(), AgentTerminalRefusalV1> {
        Err(AgentTerminalRefusalV1::Denied)
    }

    fn release_agent_terminal(
        &mut self,
        _session: protocol::AgentSessionIdV1,
        _terminal_id: &[u8],
    ) -> Result<(), AgentTerminalRefusalV1> {
        Err(AgentTerminalRefusalV1::Denied)
    }

    fn release_agent_terminals(&mut self, _session: protocol::AgentSessionIdV1) {}
}

#[derive(Clone, Default)]
pub struct StaticAcpProfileResolver {
    profiles: BTreeMap<protocol::HarnessProfileIdV1, AgentProfileSnapshotV1>,
}

impl StaticAcpProfileResolver {
    pub fn try_new(profiles: &[AcpLaunchProfileV1]) -> Option<Self> {
        let mut values = BTreeMap::new();
        for profile in profiles {
            if values
                .insert(profile.snapshot.harness_profile, profile.snapshot.clone())
                .is_some()
            {
                return None;
            }
        }
        Some(Self { profiles: values })
    }
}

impl AgentProfileResolver for StaticAcpProfileResolver {
    fn resolve_agent_profile(
        &mut self,
        _service_session: &AuthenticatedSessionV1,
        request: &AgentOpenRequestV1,
    ) -> Result<AgentProfileSnapshotV1, ProfileRefusalV1> {
        self.profiles
            .get(&request.execution.profile)
            .cloned()
            .ok_or(ProfileRefusalV1::Unknown)
    }
}

impl AcpProvider {
    pub fn try_new(
        limits: AcpLimitsV1,
        profiles: Vec<AcpLaunchProfileV1>,
        workspaces: Vec<AcpWorkspaceV1>,
    ) -> Result<Self, AcpConfigurationErrorV1> {
        Self::try_new_with_client_ports(
            limits,
            profiles,
            workspaces,
            Box::new(DisabledFileReader),
            Box::new(DisabledTerminal),
        )
    }

    pub fn try_new_with_file_reader(
        limits: AcpLimitsV1,
        profiles: Vec<AcpLaunchProfileV1>,
        workspaces: Vec<AcpWorkspaceV1>,
        file_reader: Box<dyn AgentClientFileReader>,
    ) -> Result<Self, AcpConfigurationErrorV1> {
        Self::try_new_with_client_ports(
            limits,
            profiles,
            workspaces,
            file_reader,
            Box::new(DisabledTerminal),
        )
    }

    pub fn try_new_with_terminal(
        limits: AcpLimitsV1,
        profiles: Vec<AcpLaunchProfileV1>,
        workspaces: Vec<AcpWorkspaceV1>,
        terminal: Box<dyn AgentClientTerminal>,
    ) -> Result<Self, AcpConfigurationErrorV1> {
        Self::try_new_with_client_ports(
            limits,
            profiles,
            workspaces,
            Box::new(DisabledFileReader),
            terminal,
        )
    }

    pub fn try_new_with_client_ports(
        limits: AcpLimitsV1,
        profiles: Vec<AcpLaunchProfileV1>,
        workspaces: Vec<AcpWorkspaceV1>,
        file_reader: Box<dyn AgentClientFileReader>,
        terminal: Box<dyn AgentClientTerminal>,
    ) -> Result<Self, AcpConfigurationErrorV1> {
        if !valid_limits(limits) {
            return Err(AcpConfigurationErrorV1::InvalidLimits);
        }
        let mut profile_map = BTreeMap::new();
        for profile in profiles {
            if profile.snapshot.wire != AgentWireProfileV1::AgentClientProtocol
                || !profile.program.is_absolute()
                || profile.arguments.len() > 256
                || profile.inherited_environment_names.len() > 128
                || profile
                    .agent_authentication_method
                    .as_deref()
                    .is_some_and(|value| !valid_auth_method_id(value))
                || profile
                    .inherited_environment_names
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != profile.inherited_environment_names.len()
            {
                return Err(AcpConfigurationErrorV1::InvalidProfile);
            }
            if profile_map
                .insert(profile.snapshot.document_digest, profile)
                .is_some()
            {
                return Err(AcpConfigurationErrorV1::DuplicateProfile);
            }
        }
        let mut workspace_map = BTreeMap::new();
        for workspace in workspaces {
            if !workspace.path.is_absolute()
                || !workspace.path.is_dir()
                || workspace.path.to_str().is_none()
            {
                return Err(AcpConfigurationErrorV1::InvalidWorkspace);
            }
            if workspace_map
                .insert(workspace.identity, workspace.path)
                .is_some()
            {
                return Err(AcpConfigurationErrorV1::DuplicateWorkspace);
            }
        }
        Ok(Self {
            limits,
            profiles: profile_map,
            workspaces: workspace_map,
            sessions: BTreeMap::new(),
            file_reader,
            terminal,
        })
    }

    fn prompt(
        &mut self,
        request: &AgentTurnRequestV1,
        context: &[protocol::ContextEvidenceV1],
        now: u64,
    ) -> AgentProviderOutcomeV1 {
        let Some(session) = self.sessions.get_mut(&request.session) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if session.pending.is_some() {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let Ok(prompt) = std::str::from_utf8(&request.prompt) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let Some(request_id) = session.next_id() else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let Some(prompt_blocks) = prompt_blocks(
            &session.open_context,
            context,
            prompt,
            self.limits.max_context_bytes,
        ) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if write_message(
            &mut session.stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "session/prompt",
                "params": {
                    "sessionId": session.remote_session,
                    "prompt": prompt_blocks
                }
            }),
        )
        .is_err()
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        session.pending = Some(PendingTurn {
            turn: request.turn,
            prompt_request_id: request_id,
            execution: request.execution.clone(),
            now,
            permission: None,
        });
        drain(
            session,
            request.session,
            self.limits.slice_wait,
            self.limits,
            self.file_reader.as_mut(),
            self.terminal.as_mut(),
            true,
        )
    }

    fn advance(
        &mut self,
        session_id: protocol::AgentSessionIdV1,
        turn: protocol::AgentTurnIdV1,
        now: u64,
    ) -> AgentProviderOutcomeV1 {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if session.pending.as_ref().map(|pending| pending.turn) != Some(turn)
            || session
                .pending
                .as_ref()
                .is_some_and(|pending| pending.permission.is_some())
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        if let Some(pending) = session.pending.as_mut() {
            pending.now = now;
        }
        drain(
            session,
            session_id,
            self.limits.slice_wait,
            self.limits,
            self.file_reader.as_mut(),
            self.terminal.as_mut(),
            true,
        )
    }

    fn decide_permission(
        &mut self,
        session_id: protocol::AgentSessionIdV1,
        decision: AgentPermissionDecisionV1,
        now: u64,
    ) -> AgentProviderOutcomeV1 {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let Some(pending) = session.pending.as_mut() else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let Some(permission) = pending.permission.take() else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if permission.request != decision.request {
            pending.permission = Some(permission);
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let Some(remote_option) = permission.options.get(&decision.option) else {
            pending.permission = Some(permission);
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if write_message(
            &mut session.stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": permission.rpc_id,
                "result": {"outcome": {"outcome": "selected", "optionId": remote_option}}
            }),
        )
        .is_err()
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        if let Some(pending) = session.pending.as_mut() {
            pending.now = now;
        }
        drain(
            session,
            session_id,
            self.limits.slice_wait,
            self.limits,
            self.file_reader.as_mut(),
            self.terminal.as_mut(),
            true,
        )
    }

    fn cancel(
        &mut self,
        session_id: protocol::AgentSessionIdV1,
        turn: protocol::AgentTurnIdV1,
    ) -> AgentProviderOutcomeV1 {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if session.pending.as_ref().map(|pending| pending.turn) != Some(turn) {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        self.terminal.release_agent_terminals(session_id);
        session.terminal_waits.clear();
        if let Some(permission) = session
            .pending
            .as_mut()
            .and_then(|pending| pending.permission.take())
        {
            let _ = write_message(
                &mut session.stdin,
                &json!({
                    "jsonrpc": "2.0",
                    "id": permission.rpc_id,
                    "result": {"outcome": {"outcome": "cancelled"}}
                }),
            );
        }
        if write_message(
            &mut session.stdin,
            &json!({
                "jsonrpc": "2.0",
                "method": "session/cancel",
                "params": {"sessionId": session.remote_session}
            }),
        )
        .is_err()
        {
            self.terminal.release_agent_terminals(session_id);
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        drain(
            session,
            session_id,
            self.limits.cancellation_timeout,
            self.limits,
            self.file_reader.as_mut(),
            self.terminal.as_mut(),
            false,
        )
    }

    fn close(&mut self, session_id: protocol::AgentSessionIdV1) -> AgentProviderOutcomeV1 {
        let Some(mut session) = self.sessions.remove(&session_id) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        self.terminal.release_agent_terminals(session_id);
        if session.pending.is_some() {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        if session.close_supported {
            let Some(request_id) = session.next_id() else {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            };
            if write_message(
                &mut session.stdin,
                &json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "session/close",
                    "params": {"sessionId": session.remote_session}
                }),
            )
            .is_err()
                || wait_response(&mut session, request_id, self.limits.close_timeout)
                    .is_none_or(|response| !acceptable_close_response(&response))
            {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            }
        }
        let _ = session.child.kill();
        let _ = session.child.wait();
        AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
            session: session_id,
            provider_document_digest: session.profile_digest,
            phase: AgentSessionPhaseV1::Closed,
            active_turn: None,
            capabilities: AgentCapabilitiesV1::default(),
            recovery: None,
            events: Vec::new(),
        })
    }
}

impl AgentProvider for AcpProvider {
    fn invoke_agent(&mut self, invocation: &AgentProviderInvocationV1) -> AgentProviderOutcomeV1 {
        match invocation {
            AgentProviderInvocationV1::Open {
                request,
                profile,
                context,
            } => self.open(request, profile, context),
            AgentProviderInvocationV1::Reattach {
                session,
                original_open,
                profile,
                context,
                recovery,
                ..
            } => self.reattach(*session, original_open, profile, context, recovery),
            AgentProviderInvocationV1::Prompt {
                request,
                context,
                now,
                ..
            } => self.prompt(request, context, *now),
            AgentProviderInvocationV1::Advance {
                session, turn, now, ..
            } => self.advance(*session, *turn, *now),
            AgentProviderInvocationV1::DecidePermission {
                session,
                decision,
                now,
                ..
            } => self.decide_permission(*session, *decision, *now),
            AgentProviderInvocationV1::Cancel { session, turn, .. } => self.cancel(*session, *turn),
            AgentProviderInvocationV1::Close { session, .. } => self.close(*session),
        }
    }
}

impl AcpSession {
    fn next_id(&mut self) -> Option<u64> {
        let value = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1)?;
        Some(value)
    }
}

fn spawn(
    launch: &AcpLaunchProfileV1,
    workspace: &PathBuf,
    limits: AcpLimitsV1,
) -> Option<AcpSession> {
    let mut command = launch.isolation.command(&launch.program).ok()?;
    command
        .args(&launch.arguments)
        .current_dir(workspace)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in &launch.inherited_environment_names {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().ok()?;
    let stdin = child.stdin.take()?;
    let stdout = child.stdout.take()?;
    let (sender, frames) = mpsc::sync_channel(limits.max_events_per_slice.saturating_mul(4).max(8));
    thread::Builder::new()
        .name("daimon-acp-reader".to_owned())
        .spawn(move || read_frames(stdout, limits.max_line_bytes, sender))
        .ok()?;
    Some(AcpSession {
        child,
        stdin,
        frames,
        remote_session: String::new(),
        profile_digest: launch.snapshot.document_digest,
        capabilities: AgentCapabilitiesV1::default(),
        close_supported: false,
        next_request_id: 1,
        next_cursor: 0,
        pending: None,
        open_context: Vec::new(),
        workspace: [0; 16],
        file_read_enabled: false,
        terminal_enabled: false,
        terminal_waits: Vec::new(),
    })
}

fn read_frames(mut stdout: impl Read, maximum: usize, sender: mpsc::SyncSender<ReadFrame>) {
    loop {
        let mut bytes = Vec::new();
        if bytes.try_reserve(maximum.min(8 * 1024)).is_err() {
            let _ = sender.send(ReadFrame::Invalid);
            return;
        }
        loop {
            let mut byte = [0_u8; 1];
            match stdout.read(&mut byte) {
                Ok(0) if bytes.is_empty() => {
                    let _ = sender.send(ReadFrame::Eof);
                    return;
                }
                Ok(0) => {
                    let _ = sender.send(ReadFrame::Invalid);
                    return;
                }
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) if bytes.len() < maximum => bytes.push(byte[0]),
                Ok(_) => {
                    let _ = sender.send(ReadFrame::Invalid);
                    return;
                }
                Err(_) => {
                    let _ = sender.send(ReadFrame::Invalid);
                    return;
                }
            }
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        let frame = serde_json::from_slice(&bytes)
            .ok()
            .filter(valid_jsonrpc_message)
            .map_or(ReadFrame::Invalid, ReadFrame::Message);
        if sender.send(frame).is_err() {
            return;
        }
    }
}

fn write_message(stdin: &mut ChildStdin, value: &Value) -> Result<(), ()> {
    serde_json::to_writer(&mut *stdin, value).map_err(|_| ())?;
    stdin.write_all(b"\n").map_err(|_| ())?;
    stdin.flush().map_err(|_| ())
}

fn wait_response(session: &mut AcpSession, id: u64, timeout: Duration) -> Option<Value> {
    let deadline = Instant::now().checked_add(timeout)?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match session.frames.recv_timeout(remaining) {
            Ok(ReadFrame::Message(message)) if response_id(&message) == Some(id) => {
                return Some(message);
            }
            Ok(ReadFrame::Message(message))
                if message.get("method").and_then(Value::as_str).is_some() =>
            {
                respond_unsupported(&mut session.stdin, &message);
            }
            Ok(ReadFrame::Message(_)) => return None,
            Ok(ReadFrame::Invalid | ReadFrame::Eof) | Err(_) => return None,
        }
    }
}

fn drain(
    session: &mut AcpSession,
    session_id: protocol::AgentSessionIdV1,
    wait: Duration,
    limits: AcpLimitsV1,
    file_reader: &mut dyn AgentClientFileReader,
    terminal: &mut dyn AgentClientTerminal,
    allow_file_reads: bool,
) -> AgentProviderOutcomeV1 {
    let Some(turn) = session.pending.as_ref().map(|pending| pending.turn) else {
        return AgentProviderOutcomeV1::OutcomeUnknown;
    };
    let deadline = Instant::now()
        .checked_add(wait)
        .unwrap_or_else(Instant::now);
    let mut events = Vec::new();
    loop {
        if complete_terminal_waits(session, session_id, terminal).is_err() {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        if events.len() >= limits.max_events_per_slice {
            return active_receipt(session, session_id, turn, events);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let frame = match session.frames.recv_timeout(remaining) {
            Ok(frame) => frame,
            Err(RecvTimeoutError::Timeout) => {
                return active_receipt(session, session_id, turn, events);
            }
            Err(RecvTimeoutError::Disconnected) => return AgentProviderOutcomeV1::OutcomeUnknown,
        };
        let ReadFrame::Message(message) = frame else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let prompt_id = session
            .pending
            .as_ref()
            .map(|pending| pending.prompt_request_id)
            .unwrap_or(u64::MAX);
        if response_id(&message) == Some(prompt_id) {
            let Some(reason) = message
                .pointer("/result/stopReason")
                .and_then(Value::as_str)
            else {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            };
            let Some((disposition, stop_reason)) = terminal_reason(reason) else {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            };
            push_event(
                session,
                &mut events,
                AgentEventV1::TurnFinished {
                    turn,
                    disposition,
                    stop_reason,
                    output_digest: None,
                },
            );
            session.pending = None;
            return AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                session: session_id,
                provider_document_digest: session.profile_digest,
                phase: AgentSessionPhaseV1::Ready,
                active_turn: None,
                capabilities: session.capabilities,
                recovery: session_recovery(session),
                events,
            });
        }
        if message.get("method").and_then(Value::as_str).is_none() {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        if message.get("method").and_then(Value::as_str) == Some("session/request_permission") {
            let Some((permission, event)) = parse_permission(&message, session, turn, limits)
            else {
                respond_invalid(&mut session.stdin, &message);
                return AgentProviderOutcomeV1::OutcomeUnknown;
            };
            push_event(session, &mut events, AgentEventV1::Permission(event));
            if let Some(pending) = session.pending.as_mut() {
                pending.permission = Some(permission);
            }
            return AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                session: session_id,
                provider_document_digest: session.profile_digest,
                phase: AgentSessionPhaseV1::AwaitingPermission,
                active_turn: Some(turn),
                capabilities: session.capabilities,
                recovery: session_recovery(session),
                events,
            });
        }
        if message.get("method").and_then(Value::as_str) == Some("fs/read_text_file") {
            if !session.file_read_enabled {
                if respond_rpc_error(&mut session.stdin, &message, -32601, "method not found")
                    .is_err()
                {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                }
                continue;
            }
            let Some(request) =
                parse_file_read(&message, session, session_id, turn, limits.max_event_bytes)
            else {
                if respond_rpc_error(&mut session.stdin, &message, -32602, "invalid params")
                    .is_err()
                {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                }
                continue;
            };
            let result = if allow_file_reads {
                file_reader.read_agent_file(&request)
            } else {
                Err(AgentFileReadRefusalV1::Denied)
            };
            match result {
                Ok(receipt) => {
                    if !valid_file_read_receipt(&receipt, limits.max_event_bytes)
                        || write_message(
                            &mut session.stdin,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": message.get("id").expect("validated request id"),
                                "result": {"content": std::str::from_utf8(&receipt.content).expect("validated UTF-8")}
                            }),
                        )
                        .is_err()
                    {
                        return AgentProviderOutcomeV1::OutcomeUnknown;
                    }
                    push_event(
                        session,
                        &mut events,
                        AgentEventV1::FileRead {
                            path: receipt.path,
                            content_digest: receipt.content_digest,
                            content_bytes: receipt.content.len(),
                        },
                    );
                }
                Err(refusal) => {
                    let (code, message_text) = match refusal {
                        AgentFileReadRefusalV1::Invalid => (-32602, "invalid params"),
                        AgentFileReadRefusalV1::Denied => (-32_001, "permission denied"),
                        AgentFileReadRefusalV1::Limit => (-32_002, "resource limit exceeded"),
                        AgentFileReadRefusalV1::Failed => (-32603, "filesystem read failed"),
                    };
                    if respond_rpc_error(&mut session.stdin, &message, code, message_text).is_err()
                    {
                        return AgentProviderOutcomeV1::OutcomeUnknown;
                    }
                }
            }
            continue;
        }
        if message
            .get("method")
            .and_then(Value::as_str)
            .is_some_and(|method| method.starts_with("terminal/"))
        {
            if !session.terminal_enabled {
                if respond_rpc_error(&mut session.stdin, &message, -32601, "method not found")
                    .is_err()
                {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                }
                continue;
            }
            if handle_terminal_request(
                session,
                &message,
                terminal,
                TerminalDispatchContext {
                    session: session_id,
                    turn,
                    maximum: limits.max_event_bytes,
                    allow_create: allow_file_reads,
                },
                &mut events,
            )
            .is_err()
            {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            }
            continue;
        }
        if message.get("method").and_then(Value::as_str) == Some("session/update") {
            if message.get("id").is_some()
                || message.pointer("/params/sessionId").and_then(Value::as_str)
                    != Some(&session.remote_session)
            {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            }
            if let Some(event) = parse_update(&message, limits.max_event_bytes) {
                push_event(session, &mut events, event);
            }
            continue;
        }
        respond_unsupported(&mut session.stdin, &message);
    }
}

fn parse_file_read(
    message: &Value,
    session: &AcpSession,
    session_id: protocol::AgentSessionIdV1,
    turn: protocol::AgentTurnIdV1,
    maximum: usize,
) -> Option<AgentFileReadRequestV1> {
    let rpc_id = message.get("id")?;
    if !(rpc_id.is_string() || rpc_id.is_number()) {
        return None;
    }
    let params = message.get("params")?;
    if params.get("sessionId")?.as_str()? != session.remote_session {
        return None;
    }
    let path = params.get("path")?.as_str()?;
    if path.is_empty() || path.len() > maximum || !std::path::Path::new(path).is_absolute() {
        return None;
    }
    let line = optional_u64(params.get("line"))?;
    if line == Some(0) {
        return None;
    }
    let limit = optional_u64(params.get("limit"))?;
    let execution = session.pending.as_ref()?.execution.clone();
    let now = session.pending.as_ref()?.now;
    Some(AgentFileReadRequestV1 {
        session: session_id,
        turn,
        workspace: session.workspace,
        execution,
        now,
        path: path.as_bytes().to_vec(),
        line,
        limit,
    })
}

fn handle_terminal_request(
    session: &mut AcpSession,
    message: &Value,
    terminal: &mut dyn AgentClientTerminal,
    context: TerminalDispatchContext,
    events: &mut Vec<AgentEventRecordV1>,
) -> Result<(), ()> {
    let rpc_id = message
        .get("id")
        .filter(|value| value.is_string() || value.is_number())
        .ok_or(())?
        .clone();
    let method = message.get("method").and_then(Value::as_str).ok_or(())?;
    let params = message.get("params").ok_or(())?;
    if params.get("sessionId").and_then(Value::as_str) != Some(&session.remote_session) {
        return respond_rpc_error(&mut session.stdin, message, -32602, "invalid params");
    }
    match method {
        "terminal/create" => {
            let Some(request) = parse_terminal_create(
                params,
                session,
                context.session,
                context.turn,
                context.maximum,
            ) else {
                return respond_rpc_error(&mut session.stdin, message, -32602, "invalid params");
            };
            let created = if context.allow_create {
                terminal.create_agent_terminal(&request)
            } else {
                Err(AgentTerminalRefusalV1::Denied)
            };
            match created {
                Ok(created) if valid_terminal_id(&created.terminal_id) => {
                    let terminal_id = std::str::from_utf8(&created.terminal_id).map_err(|_| ())?;
                    if write_message(
                        &mut session.stdin,
                        &json!({"jsonrpc": "2.0", "id": rpc_id, "result": {"terminalId": terminal_id}}),
                    )
                    .is_err()
                    {
                        let _ = terminal
                            .release_agent_terminal(context.session, &created.terminal_id);
                        return Err(());
                    }
                    Ok(())
                }
                Ok(created) => {
                    let _ = terminal.release_agent_terminal(context.session, &created.terminal_id);
                    Err(())
                }
                Err(refusal) => respond_terminal_refusal(&mut session.stdin, message, refusal),
            }
        }
        "terminal/output" => {
            let Some(terminal_id) = parse_terminal_id(params) else {
                return respond_rpc_error(&mut session.stdin, message, -32602, "invalid params");
            };
            match terminal.output_agent_terminal(context.session, terminal_id) {
                Ok(output) if valid_terminal_output(&output, context.maximum) => {
                    let text = std::str::from_utf8(&output.output).map_err(|_| ())?;
                    let mut result = json!({"output": text, "truncated": output.truncated});
                    if let Some(exit) = output.exit.as_ref() {
                        result["exitStatus"] = terminal_exit_json(exit).ok_or(())?;
                    }
                    write_message(
                        &mut session.stdin,
                        &json!({"jsonrpc": "2.0", "id": rpc_id, "result": result}),
                    )?;
                    push_event(
                        session,
                        events,
                        AgentEventV1::Terminal {
                            stream: b"combined".to_vec(),
                            bytes: output.output,
                        },
                    );
                    Ok(())
                }
                Ok(_) => Err(()),
                Err(refusal) => respond_terminal_refusal(&mut session.stdin, message, refusal),
            }
        }
        "terminal/wait_for_exit" => {
            let Some(terminal_id) = parse_terminal_id(params) else {
                return respond_rpc_error(&mut session.stdin, message, -32602, "invalid params");
            };
            match terminal.poll_agent_terminal_exit(context.session, terminal_id) {
                Ok(Some(exit)) => write_message(
                    &mut session.stdin,
                    &json!({"jsonrpc": "2.0", "id": rpc_id, "result": terminal_exit_json(&exit).ok_or(())?}),
                ),
                Ok(None) if session.terminal_waits.len() < 32 => {
                    session.terminal_waits.push(PendingTerminalWait {
                        rpc_id,
                        terminal_id: terminal_id.to_vec(),
                    });
                    Ok(())
                }
                Ok(None) => respond_rpc_error(
                    &mut session.stdin,
                    message,
                    -32_000,
                    "terminal wait capacity reached",
                ),
                Err(refusal) => respond_terminal_refusal(&mut session.stdin, message, refusal),
            }
        }
        "terminal/kill" | "terminal/release" => {
            let Some(terminal_id) = parse_terminal_id(params) else {
                return respond_rpc_error(&mut session.stdin, message, -32602, "invalid params");
            };
            let result = if method == "terminal/kill" {
                terminal.kill_agent_terminal(context.session, terminal_id)
            } else {
                terminal.release_agent_terminal(context.session, terminal_id)
            };
            match result {
                Ok(()) => {
                    if method == "terminal/release" {
                        session
                            .terminal_waits
                            .retain(|wait| wait.terminal_id != terminal_id);
                    }
                    write_message(
                        &mut session.stdin,
                        &json!({"jsonrpc": "2.0", "id": rpc_id, "result": null}),
                    )
                }
                Err(refusal) => respond_terminal_refusal(&mut session.stdin, message, refusal),
            }
        }
        _ => respond_rpc_error(&mut session.stdin, message, -32601, "method not found"),
    }
}

fn parse_terminal_create(
    params: &Value,
    session: &AcpSession,
    session_id: protocol::AgentSessionIdV1,
    turn: protocol::AgentTurnIdV1,
    maximum: usize,
) -> Option<AgentTerminalCreateRequestV1> {
    let command = bounded_nonempty_string(params.get("command")?, 4096)?;
    let arguments = match params.get("args") {
        None => Vec::new(),
        Some(value) => {
            let values = value.as_array()?;
            if values.len() > 255 {
                return None;
            }
            values
                .iter()
                .map(|value| bounded_nonempty_string(value, 4096))
                .collect::<Option<Vec<_>>>()?
        }
    };
    let environment = match params.get("env") {
        None => Vec::new(),
        Some(value) => {
            let values = value.as_array()?;
            if values.len() > 64 {
                return None;
            }
            values
                .iter()
                .map(|value| {
                    Some((
                        bounded_nonempty_string(value.get("name")?, 256)?,
                        bounded_string(value.get("value")?, 65_536)?,
                    ))
                })
                .collect::<Option<Vec<_>>>()?
        }
    };
    let cwd = bounded_nonempty_string(params.get("cwd")?, 16_384)?;
    if !std::path::Path::new(std::str::from_utf8(&cwd).ok()?).is_absolute() {
        return None;
    }
    let output_byte_limit = optional_u64(params.get("outputByteLimit"))?;
    if output_byte_limit.is_some_and(|value| value > maximum as u64) {
        return None;
    }
    let pending = session.pending.as_ref()?;
    Some(AgentTerminalCreateRequestV1 {
        session: session_id,
        turn,
        workspace: session.workspace,
        execution: pending.execution.clone(),
        now: pending.now,
        command,
        arguments,
        environment,
        cwd,
        output_byte_limit,
    })
}

fn bounded_nonempty_string(value: &Value, maximum: usize) -> Option<Vec<u8>> {
    let value = bounded_string(value, maximum)?;
    (!value.is_empty()).then_some(value)
}

fn bounded_string(value: &Value, maximum: usize) -> Option<Vec<u8>> {
    let value = value.as_str()?.as_bytes();
    (value.len() <= maximum && !value.contains(&0)).then(|| value.to_vec())
}

fn parse_terminal_id(params: &Value) -> Option<&[u8]> {
    let value = params.get("terminalId")?.as_str()?.as_bytes();
    valid_terminal_id(value).then_some(value)
}

fn valid_terminal_id(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= 4096 && std::str::from_utf8(value).is_ok()
}

fn valid_terminal_output(output: &AgentTerminalOutputV1, maximum: usize) -> bool {
    output.output.len() <= maximum
        && std::str::from_utf8(&output.output).is_ok()
        && output
            .exit
            .as_ref()
            .is_none_or(|exit| terminal_exit_json(exit).is_some())
}

fn terminal_exit_json(exit: &daimon_host::agent::AgentTerminalExitV1) -> Option<Value> {
    let signal = match exit.signal.as_ref() {
        Some(value) if !value.is_empty() && value.len() <= 128 => {
            Some(std::str::from_utf8(value).ok()?)
        }
        Some(_) => return None,
        None => None,
    };
    Some(json!({"exitCode": exit.exit_code, "signal": signal}))
}

fn complete_terminal_waits(
    session: &mut AcpSession,
    session_id: protocol::AgentSessionIdV1,
    terminal: &mut dyn AgentClientTerminal,
) -> Result<(), ()> {
    let mut pending = Vec::new();
    for wait in std::mem::take(&mut session.terminal_waits) {
        match terminal.poll_agent_terminal_exit(session_id, &wait.terminal_id) {
            Ok(Some(exit)) => write_message(
                &mut session.stdin,
                &json!({"jsonrpc": "2.0", "id": wait.rpc_id, "result": terminal_exit_json(&exit).ok_or(())?}),
            )?,
            Ok(None) => pending.push(wait),
            Err(_) => write_message(
                &mut session.stdin,
                &json!({"jsonrpc": "2.0", "id": wait.rpc_id, "error": {"code": -32602, "message": "invalid terminal request"}}),
            )?,
        }
    }
    session.terminal_waits = pending;
    Ok(())
}

fn respond_terminal_refusal(
    stdin: &mut ChildStdin,
    message: &Value,
    refusal: AgentTerminalRefusalV1,
) -> Result<(), ()> {
    let (code, text) = match refusal {
        AgentTerminalRefusalV1::Invalid | AgentTerminalRefusalV1::NotFound => {
            (-32602, "invalid terminal request")
        }
        AgentTerminalRefusalV1::Denied => (-32_001, "permission denied"),
        AgentTerminalRefusalV1::Capacity => (-32_000, "terminal capacity reached"),
        AgentTerminalRefusalV1::Failed => (-32603, "terminal operation failed"),
    };
    respond_rpc_error(stdin, message, code, text)
}

fn optional_u64(value: Option<&Value>) -> Option<Option<u64>> {
    match value {
        None => Some(None),
        Some(value) => value.as_u64().map(Some),
    }
}

fn valid_file_read_receipt(receipt: &AgentFileReadReceiptV1, maximum: usize) -> bool {
    !receipt.path.is_empty()
        && receipt.path.len() <= maximum
        && receipt.content.len() <= maximum
        && std::str::from_utf8(&receipt.content).is_ok()
        && protocol::ContentDigestV1::new(Sha256::digest(&receipt.content).into())
            == receipt.content_digest
}

fn active_receipt(
    session: &AcpSession,
    session_id: protocol::AgentSessionIdV1,
    turn: protocol::AgentTurnIdV1,
    events: Vec<AgentEventRecordV1>,
) -> AgentProviderOutcomeV1 {
    AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
        session: session_id,
        provider_document_digest: session.profile_digest,
        phase: AgentSessionPhaseV1::TurnActive,
        active_turn: Some(turn),
        capabilities: session.capabilities,
        recovery: session_recovery(session),
        events,
    })
}

fn push_event(session: &mut AcpSession, events: &mut Vec<AgentEventRecordV1>, event: AgentEventV1) {
    events.push(AgentEventRecordV1 {
        cursor: session.next_cursor,
        event,
    });
    session.next_cursor = session.next_cursor.saturating_add(1);
}

fn session_recovery(session: &AcpSession) -> Option<AgentProviderRecoveryV1> {
    session
        .capabilities
        .resume_session
        .then(|| AgentProviderRecoveryV1 {
            locator: session.remote_session.as_bytes().to_vec(),
        })
}

fn parse_update(message: &Value, maximum: usize) -> Option<AgentEventV1> {
    let update = message.pointer("/params/update")?;
    match update.get("sessionUpdate")?.as_str()? {
        "agent_message_chunk" => Some(AgentEventV1::AssistantMessage {
            bytes: bounded_text_content(update.get("content")?, maximum)?,
        }),
        "agent_thought_chunk" => Some(AgentEventV1::Thought {
            bytes: bounded_text_content(update.get("content")?, maximum)?,
        }),
        "plan" => {
            let entries = update.get("entries")?;
            entries.as_array()?;
            Some(AgentEventV1::Plan {
                bytes: bounded_json(entries, maximum)?,
            })
        }
        "tool_call" | "tool_call_update" => {
            let remote_id = update.get("toolCallId")?.as_str()?;
            if remote_id.is_empty() || remote_id.len() > maximum {
                return None;
            }
            let title = match update.get("sessionUpdate").and_then(Value::as_str) {
                Some("tool_call") => update.get("title")?.as_str()?,
                _ => update
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("tool call"),
            }
            .as_bytes()
            .to_vec();
            let detail = bounded_json(update, maximum.saturating_sub(title.len()))?;
            Some(AgentEventV1::ToolCall { title, detail })
        }
        "usage_update" => Some(AgentEventV1::Usage {
            input_tokens: update.pointer("/usage/inputTokens")?.as_u64()?,
            output_tokens: update.pointer("/usage/outputTokens")?.as_u64()?,
        }),
        _ => None,
    }
}

fn parse_permission(
    message: &Value,
    session: &AcpSession,
    turn: protocol::AgentTurnIdV1,
    limits: AcpLimitsV1,
) -> Option<(PendingPermission, AgentPermissionRequestV1)> {
    let rpc_id = message.get("id")?.clone();
    if !(rpc_id.is_string() || rpc_id.is_number()) {
        return None;
    }
    if message.pointer("/params/sessionId")?.as_str()? != session.remote_session {
        return None;
    }
    let tool_call = message.pointer("/params/toolCall")?;
    let remote_request = tool_call.get("toolCallId")?.as_str()?;
    let title = tool_call
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("permission request");
    let options = message.pointer("/params/options")?.as_array()?;
    if options.is_empty() || options.len() > limits.max_permission_options {
        return None;
    }
    let request = permission_identity(
        &session.remote_session,
        turn,
        remote_request.as_bytes(),
        b"request",
    );
    let mut remote_options = BTreeMap::new();
    let mut public_options = Vec::new();
    public_options.try_reserve(options.len()).ok()?;
    for option in options {
        let remote_id = option.get("optionId")?.as_str()?;
        let label = option.get("name")?.as_str()?.as_bytes().to_vec();
        if label.is_empty() || label.len() > limits.max_event_bytes {
            return None;
        }
        let kind = match option.get("kind")?.as_str()? {
            "allow_once" => AgentPermissionOptionKindV1::AllowOnce,
            "allow_always" => AgentPermissionOptionKindV1::AllowAlways,
            "reject_once" => AgentPermissionOptionKindV1::RejectOnce,
            "reject_always" => AgentPermissionOptionKindV1::RejectAlways,
            _ => return None,
        };
        let local_id = option_identity(
            &session.remote_session,
            turn,
            remote_request.as_bytes(),
            remote_id.as_bytes(),
        );
        if remote_options
            .insert(local_id, Value::String(remote_id.to_owned()))
            .is_some()
        {
            return None;
        }
        public_options.push(AgentPermissionOptionV1 {
            id: local_id,
            kind,
            label,
        });
    }
    let capability = tool_call
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("tool")
        .as_bytes()
        .to_vec();
    if capability.len().saturating_add(title.len()).saturating_add(
        public_options
            .iter()
            .map(|option| option.label.len())
            .sum::<usize>(),
    ) > limits.max_event_bytes
    {
        return None;
    }
    Some((
        PendingPermission {
            rpc_id,
            request,
            options: remote_options,
        },
        AgentPermissionRequestV1 {
            request,
            turn,
            capability,
            description: title.as_bytes().to_vec(),
            options: public_options,
        },
    ))
}

fn bounded_text(value: &Value, maximum: usize) -> Option<Vec<u8>> {
    let bytes = value.as_str()?.as_bytes();
    (bytes.len() <= maximum).then(|| bytes.to_vec())
}

fn bounded_text_content(content: &Value, maximum: usize) -> Option<Vec<u8>> {
    (content.get("type").and_then(Value::as_str) == Some("text"))
        .then(|| bounded_text(content.get("text")?, maximum))?
}

fn bounded_json(value: &Value, maximum: usize) -> Option<Vec<u8>> {
    let bytes = serde_json::to_vec(value).ok()?;
    (bytes.len() <= maximum).then_some(bytes)
}

fn prompt_blocks(
    open: &[protocol::ContextEvidenceV1],
    turn: &[protocol::ContextEvidenceV1],
    prompt: &str,
    maximum_context_bytes: usize,
) -> Option<Vec<Value>> {
    if context_bytes(open).saturating_add(context_bytes(turn)) > maximum_context_bytes {
        return None;
    }
    let mut blocks = Vec::new();
    blocks
        .try_reserve(open.len().saturating_add(turn.len()).saturating_add(1))
        .ok()?;
    let mut projected = 0_usize;
    for evidence in open.iter().chain(turn) {
        let content = std::str::from_utf8(&evidence.bytes).ok()?;
        let kind = match evidence.kind {
            protocol::ContextKindV1::AgoraMessage => "agora-message",
            protocol::ContextKindV1::ChronosWork => "chronos-work",
            protocol::ContextKindV1::VellumDocument => "vellum-document",
            protocol::ContextKindV1::DendriteGrounding => "dendrite-grounding",
        };
        let text = format!(
            "[daimon-context kind={kind} reference={} source={}]\n{content}\n[/daimon-context]",
            hex(&evidence.reference.into_bytes()),
            hex(&evidence.source_digest.into_bytes())
        );
        projected = projected.checked_add(text.len())?;
        if projected > maximum_context_bytes {
            return None;
        }
        blocks.push(json!({"type": "text", "text": text}));
    }
    blocks.push(json!({"type": "text", "text": prompt}));
    Some(blocks)
}

fn context_bytes(values: &[protocol::ContextEvidenceV1]) -> usize {
    values
        .iter()
        .map(|value| value.bytes.len().saturating_add(160))
        .sum()
}

fn hex<const N: usize>(bytes: &[u8; N]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(N.saturating_mul(2));
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}

fn permission_identity(
    session: &str,
    turn: protocol::AgentTurnIdV1,
    remote: &[u8],
    domain: &[u8],
) -> protocol::AgentPermissionRequestIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(session.as_bytes());
    hasher.update(turn.into_bytes());
    hasher.update(remote);
    let digest: [u8; 32] = hasher.finalize().into();
    protocol::AgentPermissionRequestIdV1::new(digest[..16].try_into().expect("fixed digest"))
}

fn option_identity(
    session: &str,
    turn: protocol::AgentTurnIdV1,
    request: &[u8],
    option: &[u8],
) -> protocol::AgentPermissionOptionIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(b"option");
    hasher.update(session.as_bytes());
    hasher.update(turn.into_bytes());
    hasher.update(request);
    hasher.update(option);
    let digest: [u8; 32] = hasher.finalize().into();
    protocol::AgentPermissionOptionIdV1::new(digest[..16].try_into().expect("fixed digest"))
}

fn response_id(message: &Value) -> Option<u64> {
    message.get("id")?.as_u64()
}

fn valid_jsonrpc_message(message: &Value) -> bool {
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return false;
    }
    let id = message.get("id");
    if id.is_some_and(|value| !(value.is_null() || value.is_string() || value.as_i64().is_some())) {
        return false;
    }
    if message.get("method").and_then(Value::as_str).is_some() {
        return message.get("result").is_none() && message.get("error").is_none();
    }
    if id.is_none() || (message.get("result").is_some() == message.get("error").is_some()) {
        return false;
    }
    message.get("error").is_none_or(|error| {
        error.get("code").and_then(Value::as_i64).is_some()
            && error.get("message").and_then(Value::as_str).is_some()
    })
}

fn acceptable_close_response(message: &Value) -> bool {
    message.get("result").is_some()
        || message.pointer("/error/code").and_then(Value::as_i64) == Some(-32_002)
}

fn terminal_reason(
    value: &str,
) -> Option<(protocol::ExecutionDispositionV1, AgentTurnStopReasonV1)> {
    Some(match value {
        "end_turn" | "max_tokens" | "max_turn_requests" => (
            protocol::ExecutionDispositionV1::Completed,
            AgentTurnStopReasonV1::EndTurn,
        ),
        "cancelled" => (
            protocol::ExecutionDispositionV1::Cancelled,
            AgentTurnStopReasonV1::Cancelled,
        ),
        "refusal" => (
            protocol::ExecutionDispositionV1::Failed,
            AgentTurnStopReasonV1::Failed,
        ),
        _ => return None,
    })
}

fn parse_capabilities(result: &Value) -> (AgentCapabilitiesV1, bool) {
    let capabilities = result.get("agentCapabilities").unwrap_or(&Value::Null);
    let session = capabilities
        .get("sessionCapabilities")
        .unwrap_or(&Value::Null);
    (
        AgentCapabilitiesV1 {
            load_session: capabilities
                .get("loadSession")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            resume_session: advertised_object_capability(session, "resume"),
            permissions: true,
            filesystem_read: false,
            filesystem_write: false,
            terminal: false,
            session_modes: false,
            session_models: false,
        },
        advertised_object_capability(session, "close"),
    )
}

fn advertised_object_capability(parent: &Value, name: &str) -> bool {
    parent.get(name).is_some_and(Value::is_object)
}

fn valid_session_mode_state(setup: &Value) -> bool {
    let Some(state) = setup.get("modes") else {
        return false;
    };
    let Some(current) = state.get("currentModeId").and_then(Value::as_str) else {
        return false;
    };
    state
        .get("availableModes")
        .and_then(Value::as_array)
        .is_some_and(|modes| {
            modes.iter().any(|mode| {
                mode.get("id").and_then(Value::as_str) == Some(current)
                    && mode.get("name").and_then(Value::as_str).is_some()
            }) && modes.iter().all(|mode| {
                mode.get("id").and_then(Value::as_str).is_some()
                    && mode.get("name").and_then(Value::as_str).is_some()
            })
        })
}

fn valid_session_model_state(setup: &Value) -> bool {
    let Some(state) = setup.get("models") else {
        return false;
    };
    let Some(current) = state.get("currentModelId").and_then(Value::as_str) else {
        return false;
    };
    state
        .get("availableModels")
        .and_then(Value::as_array)
        .is_some_and(|models| {
            models.iter().any(|model| {
                model.get("modelId").and_then(Value::as_str) == Some(current)
                    && model.get("name").and_then(Value::as_str).is_some()
            }) && models.iter().all(|model| {
                model.get("modelId").and_then(Value::as_str).is_some()
                    && model.get("name").and_then(Value::as_str).is_some()
            })
        })
}

fn respond_invalid(stdin: &mut ChildStdin, message: &Value) {
    if let Some(id) = message.get("id") {
        let _ = write_message(
            stdin,
            &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": "invalid params"}}),
        );
    }
}

fn respond_rpc_error(
    stdin: &mut ChildStdin,
    message: &Value,
    code: i64,
    text: &str,
) -> Result<(), ()> {
    let id = message.get("id").ok_or(())?;
    if !(id.is_string() || id.is_number()) {
        return Err(());
    }
    write_message(
        stdin,
        &json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": text}}),
    )
}

fn respond_unsupported(stdin: &mut ChildStdin, message: &Value) {
    if let Some(id) = message.get("id") {
        let _ = write_message(
            stdin,
            &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}}),
        );
    }
}

fn valid_limits(limits: AcpLimitsV1) -> bool {
    (1..=4_096).contains(&limits.max_sessions)
        && (1..=64 * 1024 * 1024).contains(&limits.max_line_bytes)
        && (1..=65_536).contains(&limits.max_events_per_slice)
        && (1..=16 * 1024 * 1024).contains(&limits.max_event_bytes)
        && (1..=64 * 1024 * 1024).contains(&limits.max_context_bytes)
        && (1..=256).contains(&limits.max_permission_options)
        && !limits.startup_timeout.is_zero()
        && !limits.slice_wait.is_zero()
        && !limits.cancellation_timeout.is_zero()
        && !limits.close_timeout.is_zero()
}

impl AcpProvider {
    fn open(
        &mut self,
        request: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
        context: &[protocol::ContextEvidenceV1],
    ) -> AgentProviderOutcomeV1 {
        self.connect(request, profile, context, None)
    }

    fn reattach(
        &mut self,
        session_id: protocol::AgentSessionIdV1,
        original_open: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
        context: &[protocol::ContextEvidenceV1],
        recovery: &AgentProviderRecoveryV1,
    ) -> AgentProviderOutcomeV1 {
        if session_id != original_open.session {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        self.connect(original_open, profile, context, Some(recovery))
    }

    fn connect(
        &mut self,
        request: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
        context: &[protocol::ContextEvidenceV1],
        recovery: Option<&AgentProviderRecoveryV1>,
    ) -> AgentProviderOutcomeV1 {
        if self.sessions.len() >= self.limits.max_sessions
            || self.sessions.contains_key(&request.session)
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let Some(launch) = self.profiles.get(&profile.document_digest) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if launch.snapshot != *profile {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let Some(workspace) = self.workspaces.get(&request.workspace) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let file_read_enabled = self.file_reader.supports_agent_file_read(request, profile);
        let terminal_enabled = self.terminal.supports_agent_terminal(request, profile);
        let Some(mut session) = spawn(launch, workspace, self.limits) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        session.workspace = request.workspace;
        session.file_read_enabled = file_read_enabled;
        session.terminal_enabled = terminal_enabled;
        let Some(initialize_id) = session.next_id() else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if write_message(
            &mut session.stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": initialize_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": 1,
                    "clientCapabilities": {
                        "fs": {"readTextFile": file_read_enabled, "writeTextFile": false},
                        "terminal": terminal_enabled
                    },
                    "clientInfo": {"name": "daimon", "version": env!("CARGO_PKG_VERSION")}
                }
            }),
        )
        .is_err()
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let Some(initialize) =
            wait_response(&mut session, initialize_id, self.limits.startup_timeout)
        else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let Some(result) = initialize.get("result") else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if result.get("protocolVersion").and_then(Value::as_u64) != Some(1) {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        if let Some(method_id) = launch.agent_authentication_method.as_deref() {
            let Some(methods) = result.get("authMethods").and_then(Value::as_array) else {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            };
            let mut matches = methods
                .iter()
                .filter(|method| method.get("id").and_then(Value::as_str) == Some(method_id));
            let Some(method) = matches.next() else {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            };
            if matches.next().is_some()
                || method
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind != "agent")
            {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            }
            let Some(authentication_id) = session.next_id() else {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            };
            if write_message(
                &mut session.stdin,
                &json!({
                    "jsonrpc": "2.0",
                    "id": authentication_id,
                    "method": "authenticate",
                    "params": {"methodId": method_id}
                }),
            )
            .is_err()
            {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            }
            let Some(authenticated) =
                wait_response(&mut session, authentication_id, self.limits.startup_timeout)
            else {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            };
            if authenticated.get("result").is_none() {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            }
        }
        let (mut capabilities, close_supported) = parse_capabilities(result);
        capabilities.filesystem_read = file_read_enabled;
        capabilities.terminal = terminal_enabled;
        session.capabilities = capabilities;
        session.close_supported = close_supported;
        if recovery.is_some() && !capabilities.resume_session {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let Some(new_id) = session.next_id() else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let recovered_remote = recovery.and_then(|value| {
            std::str::from_utf8(&value.locator)
                .ok()
                .filter(|remote| !remote.is_empty() && remote.len() <= 4_096)
        });
        if recovery.is_some() && recovered_remote.is_none() {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let (method, params) = match recovered_remote {
            Some(remote_session) => (
                "session/resume",
                json!({
                    "sessionId": remote_session,
                    "cwd": workspace.to_str().expect("validated workspace"),
                    "mcpServers": []
                }),
            ),
            None => (
                "session/new",
                json!({
                    "cwd": workspace.to_str().expect("validated workspace"),
                    "mcpServers": []
                }),
            ),
        };
        if write_message(
            &mut session.stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": new_id,
                "method": method,
                "params": params
            }),
        )
        .is_err()
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let Some(created) = wait_response(&mut session, new_id, self.limits.startup_timeout) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let Some(setup) = created.get("result") else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let remote_session = match recovered_remote {
            Some(remote_session) => remote_session,
            None => {
                let Some(remote_session) = setup
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty() && value.len() <= 4_096)
                else {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                };
                remote_session
            }
        };
        capabilities.session_modes = valid_session_mode_state(setup);
        capabilities.session_models = valid_session_model_state(setup);
        session.capabilities = capabilities;
        session.remote_session = remote_session.to_owned();
        if context_bytes(context) > self.limits.max_context_bytes {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        session.open_context = context.to_vec();
        let receipt = AgentProviderReceiptV1 {
            session: request.session,
            provider_document_digest: profile.document_digest,
            phase: AgentSessionPhaseV1::Ready,
            active_turn: None,
            capabilities,
            recovery: capabilities
                .resume_session
                .then(|| AgentProviderRecoveryV1 {
                    locator: remote_session.as_bytes().to_vec(),
                }),
            events: Vec::new(),
        };
        self.sessions.insert(request.session, session);
        AgentProviderOutcomeV1::Receipt(receipt)
    }
}

fn valid_auth_method_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::{acceptable_close_response, valid_jsonrpc_message};
    use serde_json::json;

    #[test]
    fn close_accepts_success_and_session_not_found_only() {
        assert!(acceptable_close_response(&json!({"result": {}})));
        assert!(acceptable_close_response(
            &json!({"error": {"code": -32002, "message": "session not found"}})
        ));
        assert!(!acceptable_close_response(
            &json!({"error": {"code": -32603, "message": "internal error"}})
        ));
    }

    #[test]
    fn jsonrpc_envelopes_require_version_valid_identity_and_one_message_shape() {
        assert!(valid_jsonrpc_message(
            &json!({"jsonrpc": "2.0", "id": 1, "result": {}})
        ));
        assert!(valid_jsonrpc_message(
            &json!({"jsonrpc": "2.0", "method": "session/update", "params": {}})
        ));
        assert!(valid_jsonrpc_message(
            &json!({"jsonrpc": "2.0", "id": "permission", "method": "session/request_permission", "params": {}})
        ));
        for malformed in [
            json!({"id": 1, "result": {}}),
            json!({"jsonrpc": "1.0", "id": 1, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 1.5, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1, "message": "both"}}),
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": "-1", "message": "bad code"}}),
            json!({"jsonrpc": "2.0", "method": "session/update", "result": {}}),
        ] {
            assert!(!valid_jsonrpc_message(&malformed), "{malformed}");
        }
    }
}
