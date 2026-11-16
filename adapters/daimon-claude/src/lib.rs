//! Bounded Claude Agent SDK stream-JSON projection for Daimon agent sessions.
//!
//! This adapter implements Claude Code's bidirectional NDJSON/control channel;
//! it does not present that provider-specific transport as ACP. Launch material
//! and workspace paths remain host-owned registry state.

#![forbid(unsafe_code)]

use daimon_host::agent::{
    AgentProfileResolver, AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1,
    AgentProviderReceiptV1,
};
use daimon_host::{AuthenticatedSessionV1, ProfileRefusalV1};
pub use daimon_process::ProcessIsolationV1;
use daimon_protocol::{self as protocol, agent::*};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    io::{Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

const REQUIRED_ARGUMENTS: [&str; 9] = [
    "--output-format",
    "stream-json",
    "--verbose",
    "--input-format",
    "stream-json",
    "--permission-prompt-tool",
    "stdio",
    "--permission-mode",
    "default",
];

const RESERVED_ARGUMENTS: [&str; 5] = [
    "--output-format",
    "--input-format",
    "--permission-prompt-tool",
    "--permission-mode",
    "--verbose",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaudeLimitsV1 {
    pub max_sessions: usize,
    pub max_line_bytes: usize,
    pub max_events_per_slice: usize,
    pub max_event_bytes: usize,
    pub max_context_bytes: usize,
    pub startup_timeout: Duration,
    pub slice_wait: Duration,
    pub cancellation_timeout: Duration,
    pub close_timeout: Duration,
}

impl Default for ClaudeLimitsV1 {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            max_line_bytes: 4 * 1024 * 1024,
            max_events_per_slice: 128,
            max_event_bytes: 1024 * 1024,
            max_context_bytes: 4 * 1024 * 1024,
            startup_timeout: Duration::from_secs(10),
            slice_wait: Duration::from_millis(25),
            cancellation_timeout: Duration::from_secs(5),
            close_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone)]
pub struct ClaudeLaunchProfileV1 {
    pub snapshot: AgentProfileSnapshotV1,
    pub program: PathBuf,
    /// Administrator-owned arguments appended after the adapter's mandatory
    /// transport flags. Reserved transport flags are rejected at construction.
    pub arguments: Vec<OsString>,
    /// Exact environment names copied from the host after `env_clear`.
    pub inherited_environment_names: Vec<OsString>,
    pub isolation: ProcessIsolationV1,
}

impl std::fmt::Debug for ClaudeLaunchProfileV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaudeLaunchProfileV1")
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
            .field("isolation", &self.isolation)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeWorkspaceV1 {
    pub identity: [u8; 16],
    pub path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaudeConfigurationErrorV1 {
    InvalidLimits,
    InvalidProfile,
    DuplicateProfile,
    InvalidWorkspace,
    DuplicateWorkspace,
}

#[derive(Clone, Default)]
pub struct StaticClaudeProfileResolver {
    profiles: BTreeMap<protocol::HarnessProfileIdV1, AgentProfileSnapshotV1>,
}

impl StaticClaudeProfileResolver {
    pub fn try_new(profiles: &[ClaudeLaunchProfileV1]) -> Option<Self> {
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

impl AgentProfileResolver for StaticClaudeProfileResolver {
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

enum ReadFrame {
    Message(Value),
    Invalid,
    Eof,
}

#[derive(Clone, Copy)]
enum PermissionChoice {
    Allow,
    Reject,
}

struct PendingPermission {
    control_request_id: String,
    request: protocol::AgentPermissionRequestIdV1,
    original_input: Value,
    options: BTreeMap<protocol::AgentPermissionOptionIdV1, PermissionChoice>,
}

struct PendingTurn {
    turn: protocol::AgentTurnIdV1,
    permission: Option<PendingPermission>,
}

struct ClaudeSession {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: Receiver<ReadFrame>,
    profile_digest: protocol::ContentDigestV1,
    next_control_id: u64,
    next_cursor: u64,
    pending: Option<PendingTurn>,
    open_context: Vec<protocol::ContextEvidenceV1>,
}

impl ClaudeSession {
    fn next_control_id(&mut self, prefix: &str) -> Option<String> {
        let value = self.next_control_id;
        self.next_control_id = self.next_control_id.checked_add(1)?;
        Some(format!("daimon-{prefix}-{value}"))
    }

    fn write(&mut self, value: &Value) -> Result<(), ()> {
        write_message(self.stdin.as_mut().ok_or(())?, value)
    }

    fn write_control_success(&mut self, request_id: &str, response: Value) -> Result<(), ()> {
        write_control_success(self.stdin.as_mut().ok_or(())?, request_id, response)
    }
}

impl Drop for ClaudeSession {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct ClaudeProvider {
    limits: ClaudeLimitsV1,
    profiles: BTreeMap<protocol::ContentDigestV1, ClaudeLaunchProfileV1>,
    workspaces: BTreeMap<[u8; 16], PathBuf>,
    sessions: BTreeMap<protocol::AgentSessionIdV1, ClaudeSession>,
}

impl ClaudeProvider {
    pub fn try_new(
        limits: ClaudeLimitsV1,
        profiles: Vec<ClaudeLaunchProfileV1>,
        workspaces: Vec<ClaudeWorkspaceV1>,
    ) -> Result<Self, ClaudeConfigurationErrorV1> {
        if !valid_limits(limits) {
            return Err(ClaudeConfigurationErrorV1::InvalidLimits);
        }
        let mut profile_map = BTreeMap::new();
        for profile in profiles {
            if profile.snapshot.wire != AgentWireProfileV1::ClaudeAgentStreamJson
                || !profile.program.is_absolute()
                || profile.arguments.len() > 256
                || has_reserved_argument(&profile.arguments)
                || profile.inherited_environment_names.len() > 128
                || profile.inherited_environment_names.iter().any(|name| {
                    name.is_empty()
                        || name.to_str().is_none()
                        || name == OsStr::new("CLAUDE_CODE_SDK_READS_SESSION_STATE")
                })
                || profile
                    .inherited_environment_names
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != profile.inherited_environment_names.len()
            {
                return Err(ClaudeConfigurationErrorV1::InvalidProfile);
            }
            if profile_map
                .insert(profile.snapshot.document_digest, profile)
                .is_some()
            {
                return Err(ClaudeConfigurationErrorV1::DuplicateProfile);
            }
        }
        let mut workspace_map = BTreeMap::new();
        for workspace in workspaces {
            if !workspace.path.is_absolute()
                || !workspace.path.is_dir()
                || workspace.path.to_str().is_none()
            {
                return Err(ClaudeConfigurationErrorV1::InvalidWorkspace);
            }
            if workspace_map
                .insert(workspace.identity, workspace.path)
                .is_some()
            {
                return Err(ClaudeConfigurationErrorV1::DuplicateWorkspace);
            }
        }
        Ok(Self {
            limits,
            profiles: profile_map,
            workspaces: workspace_map,
            sessions: BTreeMap::new(),
        })
    }

    fn open(
        &mut self,
        request: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
        context: &[protocol::ContextEvidenceV1],
    ) -> AgentProviderOutcomeV1 {
        if self.sessions.len() >= self.limits.max_sessions
            || self.sessions.contains_key(&request.session)
            || context_bytes(context) > self.limits.max_context_bytes
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
        let Some(mut session) = spawn(launch, workspace, self.limits) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let Some(request_id) = session.next_control_id("initialize") else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if session
            .write(&json!({
                "type": "control_request",
                "request_id": request_id,
                "request": {"subtype": "initialize", "hooks": null}
            }))
            .is_err()
            || !wait_control_response(&mut session, &request_id, self.limits.startup_timeout)
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        session.open_context = context.to_vec();
        let capabilities = capabilities();
        self.sessions.insert(request.session, session);
        AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
            session: request.session,
            provider_document_digest: profile.document_digest,
            phase: AgentSessionPhaseV1::Ready,
            active_turn: None,
            capabilities,
            recovery: None,
            events: Vec::new(),
        })
    }

    fn prompt(
        &mut self,
        request: &AgentTurnRequestV1,
        context: &[protocol::ContextEvidenceV1],
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
        let Some(content) = prompt_content(
            &session.open_context,
            context,
            prompt,
            self.limits.max_context_bytes,
        ) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if session
            .write(&json!({
                "type": "user",
                "message": {"role": "user", "content": content},
                "parent_tool_use_id": null,
                "session_id": "default",
                "client_composed": true
            }))
            .is_err()
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        session.pending = Some(PendingTurn {
            turn: request.turn,
            permission: None,
        });
        drain(
            session,
            request.session,
            self.limits.slice_wait,
            self.limits,
        )
    }

    fn advance(
        &mut self,
        session_id: protocol::AgentSessionIdV1,
        turn: protocol::AgentTurnIdV1,
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
        drain(session, session_id, self.limits.slice_wait, self.limits)
    }

    fn decide_permission(
        &mut self,
        session_id: protocol::AgentSessionIdV1,
        decision: AgentPermissionDecisionV1,
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
        let Some(choice) = permission.options.get(&decision.option).copied() else {
            pending.permission = Some(permission);
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        let response = match choice {
            PermissionChoice::Allow => json!({
                "behavior": "allow",
                "updatedInput": permission.original_input
            }),
            PermissionChoice::Reject => json!({
                "behavior": "deny",
                "message": "Rejected by the Daimon authority boundary",
                "interrupt": false
            }),
        };
        if session
            .write_control_success(&permission.control_request_id, response)
            .is_err()
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        drain(session, session_id, self.limits.slice_wait, self.limits)
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
        let permission_response = session
            .pending
            .as_mut()
            .and_then(|pending| pending.permission.take())
            .map(|permission| {
                session.write_control_success(
                    &permission.control_request_id,
                    json!({
                        "behavior": "deny",
                        "message": "Cancelled by the Daimon authority boundary",
                        "interrupt": true
                    }),
                )
            });
        if permission_response.is_some_and(|result| result.is_err()) {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let Some(request_id) = session.next_control_id("interrupt") else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if session
            .write(&json!({
                "type": "control_request",
                "request_id": request_id,
                "request": {"subtype": "interrupt"}
            }))
            .is_err()
        {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        drain_until_cancelled(
            session,
            session_id,
            &request_id,
            self.limits.cancellation_timeout,
            self.limits,
        )
    }

    fn close(&mut self, session_id: protocol::AgentSessionIdV1) -> AgentProviderOutcomeV1 {
        let Some(mut session) = self.sessions.remove(&session_id) else {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        };
        if session.pending.is_some() {
            self.sessions.insert(session_id, session);
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        session.stdin.take();
        if terminate(&mut session.child, self.limits.close_timeout).is_none() {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
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

impl AgentProvider for ClaudeProvider {
    fn invoke_agent(&mut self, invocation: &AgentProviderInvocationV1) -> AgentProviderOutcomeV1 {
        match invocation {
            AgentProviderInvocationV1::Open {
                request,
                profile,
                context,
            } => self.open(request, profile, context),
            AgentProviderInvocationV1::Reattach { .. } => AgentProviderOutcomeV1::OutcomeUnknown,
            AgentProviderInvocationV1::Prompt {
                request, context, ..
            } => self.prompt(request, context),
            AgentProviderInvocationV1::Advance { session, turn, .. } => {
                self.advance(*session, *turn)
            }
            AgentProviderInvocationV1::DecidePermission {
                session, decision, ..
            } => self.decide_permission(*session, *decision),
            AgentProviderInvocationV1::Cancel { session, turn, .. } => self.cancel(*session, *turn),
            AgentProviderInvocationV1::Close { session, .. } => self.close(*session),
        }
    }
}

fn spawn(
    launch: &ClaudeLaunchProfileV1,
    workspace: &PathBuf,
    limits: ClaudeLimitsV1,
) -> Option<ClaudeSession> {
    let mut command = launch.isolation.command(&launch.program).ok()?;
    command
        .args(REQUIRED_ARGUMENTS)
        .args(&launch.arguments)
        .current_dir(workspace)
        .env_clear()
        .env("CLAUDE_CODE_SDK_READS_SESSION_STATE", "1")
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
        .name("daimon-claude-reader".to_owned())
        .spawn(move || read_frames(stdout, limits.max_line_bytes, sender))
        .ok()?;
    Some(ClaudeSession {
        child,
        stdin: Some(stdin),
        frames,
        profile_digest: launch.snapshot.document_digest,
        next_control_id: 1,
        next_cursor: 0,
        pending: None,
        open_context: Vec::new(),
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
            .filter(Value::is_object)
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

fn write_control_success(
    stdin: &mut ChildStdin,
    request_id: &str,
    response: Value,
) -> Result<(), ()> {
    write_message(
        stdin,
        &json!({
            "type": "control_response",
            "response": {
                "subtype": "success",
                "request_id": request_id,
                "response": response
            }
        }),
    )
}

fn wait_control_response(session: &mut ClaudeSession, request_id: &str, timeout: Duration) -> bool {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return false;
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match session.frames.recv_timeout(remaining) {
            Ok(ReadFrame::Message(message))
                if control_response_id(&message) == Some(request_id) =>
            {
                return message.pointer("/response/subtype").and_then(Value::as_str)
                    == Some("success")
                    && message
                        .pointer("/response/response")
                        .is_some_and(Value::is_object);
            }
            Ok(ReadFrame::Message(message)) if ignorable_system(&message) => {}
            Ok(ReadFrame::Message(_) | ReadFrame::Invalid | ReadFrame::Eof) | Err(_) => {
                return false;
            }
        }
    }
}

fn drain(
    session: &mut ClaudeSession,
    session_id: protocol::AgentSessionIdV1,
    wait: Duration,
    limits: ClaudeLimitsV1,
) -> AgentProviderOutcomeV1 {
    let Some(turn) = session.pending.as_ref().map(|pending| pending.turn) else {
        return AgentProviderOutcomeV1::OutcomeUnknown;
    };
    let deadline = Instant::now()
        .checked_add(wait)
        .unwrap_or_else(Instant::now);
    let mut events = Vec::new();
    loop {
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
        match message.get("type").and_then(Value::as_str) {
            Some("assistant") => {
                let Some(parsed) = parse_assistant(&message, limits.max_event_bytes) else {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                };
                for event in parsed {
                    if events.len() >= limits.max_events_per_slice {
                        return AgentProviderOutcomeV1::OutcomeUnknown;
                    }
                    push_event(session, &mut events, event);
                }
            }
            Some("result") => {
                let Some((disposition, stop_reason)) = terminal_reason(&message) else {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                };
                if let Some(usage) = parse_usage(&message) {
                    push_event(session, &mut events, usage);
                }
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
                return ready_receipt(session, session_id, events);
            }
            Some("control_request") => {
                let Some((permission, event)) = parse_permission(&message, turn, limits) else {
                    respond_control_error(session, &message, "unsupported control request");
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
                    capabilities: capabilities(),
                    recovery: None,
                    events,
                });
            }
            Some("system" | "user") => {}
            _ => return AgentProviderOutcomeV1::OutcomeUnknown,
        }
    }
}

fn drain_until_cancelled(
    session: &mut ClaudeSession,
    session_id: protocol::AgentSessionIdV1,
    interrupt_id: &str,
    timeout: Duration,
    limits: ClaudeLimitsV1,
) -> AgentProviderOutcomeV1 {
    let Some(turn) = session.pending.as_ref().map(|pending| pending.turn) else {
        return AgentProviderOutcomeV1::OutcomeUnknown;
    };
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return AgentProviderOutcomeV1::OutcomeUnknown;
    };
    let mut acknowledged = false;
    let mut events = Vec::new();
    loop {
        if events.len() >= limits.max_events_per_slice {
            return AgentProviderOutcomeV1::OutcomeUnknown;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let frame = match session.frames.recv_timeout(remaining) {
            Ok(ReadFrame::Message(message)) => message,
            _ => return AgentProviderOutcomeV1::OutcomeUnknown,
        };
        if control_response_id(&frame) == Some(interrupt_id) {
            if frame.pointer("/response/subtype").and_then(Value::as_str) != Some("success") {
                return AgentProviderOutcomeV1::OutcomeUnknown;
            }
            acknowledged = true;
            continue;
        }
        match frame.get("type").and_then(Value::as_str) {
            Some("assistant") => {
                let Some(parsed) = parse_assistant(&frame, limits.max_event_bytes) else {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                };
                for event in parsed {
                    push_event(session, &mut events, event);
                }
            }
            Some("result") if acknowledged => {
                push_event(
                    session,
                    &mut events,
                    AgentEventV1::TurnFinished {
                        turn,
                        disposition: protocol::ExecutionDispositionV1::Cancelled,
                        stop_reason: AgentTurnStopReasonV1::Cancelled,
                        output_digest: None,
                    },
                );
                session.pending = None;
                return ready_receipt(session, session_id, events);
            }
            Some("system" | "user") => {}
            _ => return AgentProviderOutcomeV1::OutcomeUnknown,
        }
    }
}

fn parse_assistant(message: &Value, maximum: usize) -> Option<Vec<AgentEventV1>> {
    let blocks = message.pointer("/message/content")?.as_array()?;
    let mut events = Vec::new();
    events.try_reserve(blocks.len()).ok()?;
    for block in blocks {
        let event = match block.get("type")?.as_str()? {
            "text" => AgentEventV1::AssistantMessage {
                bytes: bounded_text(block.get("text")?, maximum)?,
            },
            "thinking" | "redacted_thinking" => AgentEventV1::Thought {
                bytes: bounded_json(block, maximum)?,
            },
            "tool_use" => {
                let title = bounded_text(block.get("name")?, maximum)?;
                let detail = bounded_json(block, maximum.saturating_sub(title.len()))?;
                AgentEventV1::ToolCall { title, detail }
            }
            _ => return None,
        };
        events.push(event);
    }
    Some(events)
}

fn parse_permission(
    message: &Value,
    turn: protocol::AgentTurnIdV1,
    limits: ClaudeLimitsV1,
) -> Option<(PendingPermission, AgentPermissionRequestV1)> {
    let control_request_id = message.get("request_id")?.as_str()?;
    if control_request_id.is_empty() || control_request_id.len() > 4096 {
        return None;
    }
    let request_data = message.get("request")?;
    if request_data.get("subtype")?.as_str()? != "can_use_tool" {
        return None;
    }
    let tool_name = request_data.get("tool_name")?.as_str()?;
    let original_input = request_data.get("input")?.clone();
    if tool_name.is_empty()
        || tool_name.len() > limits.max_event_bytes
        || !original_input.is_object()
    {
        return None;
    }
    let tool_use_id = request_data
        .get("tool_use_id")
        .and_then(Value::as_str)
        .unwrap_or(control_request_id);
    let request = permission_identity(turn, control_request_id, tool_use_id);
    let allow_id = option_identity(turn, control_request_id, b"allow-once");
    let reject_id = option_identity(turn, control_request_id, b"reject-once");
    let description = request_data
        .get("title")
        .or_else(|| request_data.get("description"))
        .and_then(Value::as_str)
        .unwrap_or(tool_name)
        .as_bytes()
        .to_vec();
    if description.is_empty()
        || description
            .len()
            .saturating_add(tool_name.len())
            .saturating_add(20)
            > limits.max_event_bytes
    {
        return None;
    }
    let mut options = BTreeMap::new();
    options.insert(allow_id, PermissionChoice::Allow);
    options.insert(reject_id, PermissionChoice::Reject);
    Some((
        PendingPermission {
            control_request_id: control_request_id.to_owned(),
            request,
            original_input,
            options,
        },
        AgentPermissionRequestV1 {
            request,
            turn,
            capability: tool_name.as_bytes().to_vec(),
            description,
            options: vec![
                AgentPermissionOptionV1 {
                    id: allow_id,
                    kind: AgentPermissionOptionKindV1::AllowOnce,
                    label: b"Allow once".to_vec(),
                },
                AgentPermissionOptionV1 {
                    id: reject_id,
                    kind: AgentPermissionOptionKindV1::RejectOnce,
                    label: b"Reject once".to_vec(),
                },
            ],
        },
    ))
}

fn parse_usage(message: &Value) -> Option<AgentEventV1> {
    let usage = message.get("usage")?;
    Some(AgentEventV1::Usage {
        input_tokens: usage.get("input_tokens")?.as_u64()?,
        output_tokens: usage.get("output_tokens")?.as_u64()?,
    })
}

fn terminal_reason(
    message: &Value,
) -> Option<(protocol::ExecutionDispositionV1, AgentTurnStopReasonV1)> {
    let is_error = message.get("is_error")?.as_bool()?;
    let subtype = message.get("subtype")?.as_str()?;
    if !is_error && subtype == "success" {
        Some((
            protocol::ExecutionDispositionV1::Completed,
            AgentTurnStopReasonV1::EndTurn,
        ))
    } else {
        Some((
            protocol::ExecutionDispositionV1::Failed,
            AgentTurnStopReasonV1::Failed,
        ))
    }
}

fn prompt_content(
    open: &[protocol::ContextEvidenceV1],
    turn: &[protocol::ContextEvidenceV1],
    prompt: &str,
    maximum: usize,
) -> Option<String> {
    let mut value = String::new();
    for evidence in open.iter().chain(turn) {
        let content = std::str::from_utf8(&evidence.bytes).ok()?;
        let kind = match evidence.kind {
            protocol::ContextKindV1::AgoraMessage => "agora-message",
            protocol::ContextKindV1::ChronosWork => "chronos-work",
            protocol::ContextKindV1::VellumDocument => "vellum-document",
            protocol::ContextKindV1::DendriteGrounding => "dendrite-grounding",
        };
        let block = format!(
            "[daimon-context kind={kind} reference={} source={}]\n{content}\n[/daimon-context]\n",
            hex(&evidence.reference.into_bytes()),
            hex(&evidence.source_digest.into_bytes())
        );
        if value.len().checked_add(block.len())? > maximum {
            return None;
        }
        value.push_str(&block);
    }
    if value.len().checked_add(prompt.len())? > maximum {
        return None;
    }
    value.push_str(prompt);
    Some(value)
}

fn active_receipt(
    session: &ClaudeSession,
    session_id: protocol::AgentSessionIdV1,
    turn: protocol::AgentTurnIdV1,
    events: Vec<AgentEventRecordV1>,
) -> AgentProviderOutcomeV1 {
    AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
        session: session_id,
        provider_document_digest: session.profile_digest,
        phase: AgentSessionPhaseV1::TurnActive,
        active_turn: Some(turn),
        capabilities: capabilities(),
        recovery: None,
        events,
    })
}

fn ready_receipt(
    session: &ClaudeSession,
    session_id: protocol::AgentSessionIdV1,
    events: Vec<AgentEventRecordV1>,
) -> AgentProviderOutcomeV1 {
    AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
        session: session_id,
        provider_document_digest: session.profile_digest,
        phase: AgentSessionPhaseV1::Ready,
        active_turn: None,
        capabilities: capabilities(),
        recovery: None,
        events,
    })
}

fn push_event(
    session: &mut ClaudeSession,
    events: &mut Vec<AgentEventRecordV1>,
    event: AgentEventV1,
) {
    events.push(AgentEventRecordV1 {
        cursor: session.next_cursor,
        event,
    });
    session.next_cursor = session.next_cursor.saturating_add(1);
}

fn respond_control_error(session: &mut ClaudeSession, message: &Value, error: &str) {
    let Some(request_id) = message.get("request_id").and_then(Value::as_str) else {
        return;
    };
    let _ = session.write(&json!({
        "type": "control_response",
        "response": {
            "subtype": "error",
            "request_id": request_id,
            "error": error
        }
    }));
}

fn terminate(child: &mut Child, timeout: Duration) -> Option<()> {
    let deadline = Instant::now().checked_add(timeout)?;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Some(()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    child.kill().ok()?;
    child.wait().ok()?;
    Some(())
}

fn control_response_id(message: &Value) -> Option<&str> {
    (message.get("type")?.as_str()? == "control_response")
        .then(|| message.pointer("/response/request_id")?.as_str())?
}

fn ignorable_system(message: &Value) -> bool {
    message.get("type").and_then(Value::as_str) == Some("system")
}

fn capabilities() -> AgentCapabilitiesV1 {
    AgentCapabilitiesV1 {
        permissions: true,
        filesystem_read: false,
        filesystem_write: false,
        terminal: false,
        ..AgentCapabilitiesV1::default()
    }
}

fn permission_identity(
    turn: protocol::AgentTurnIdV1,
    control_request_id: &str,
    tool_use_id: &str,
) -> protocol::AgentPermissionRequestIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(b"claude-permission-request-v1");
    hasher.update(turn.into_bytes());
    hasher.update(control_request_id.as_bytes());
    hasher.update(tool_use_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    protocol::AgentPermissionRequestIdV1::new(digest[..16].try_into().expect("fixed digest"))
}

fn option_identity(
    turn: protocol::AgentTurnIdV1,
    control_request_id: &str,
    option: &[u8],
) -> protocol::AgentPermissionOptionIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(b"claude-permission-option-v1");
    hasher.update(turn.into_bytes());
    hasher.update(control_request_id.as_bytes());
    hasher.update(option);
    let digest: [u8; 32] = hasher.finalize().into();
    protocol::AgentPermissionOptionIdV1::new(digest[..16].try_into().expect("fixed digest"))
}

fn bounded_text(value: &Value, maximum: usize) -> Option<Vec<u8>> {
    let bytes = value.as_str()?.as_bytes();
    (bytes.len() <= maximum).then(|| bytes.to_vec())
}

fn bounded_json(value: &Value, maximum: usize) -> Option<Vec<u8>> {
    let bytes = serde_json::to_vec(value).ok()?;
    (bytes.len() <= maximum).then_some(bytes)
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

fn has_reserved_argument(arguments: &[OsString]) -> bool {
    arguments.iter().any(|argument| {
        RESERVED_ARGUMENTS.iter().any(|reserved| {
            argument == OsStr::new(reserved)
                || argument
                    .to_str()
                    .is_some_and(|value| value.starts_with(&format!("{reserved}=")))
        })
    })
}

fn valid_limits(limits: ClaudeLimitsV1) -> bool {
    (1..=4_096).contains(&limits.max_sessions)
        && (1..=64 * 1024 * 1024).contains(&limits.max_line_bytes)
        && (1..=65_536).contains(&limits.max_events_per_slice)
        && (1..=16 * 1024 * 1024).contains(&limits.max_event_bytes)
        && (1..=64 * 1024 * 1024).contains(&limits.max_context_bytes)
        && !limits.startup_timeout.is_zero()
        && !limits.slice_wait.is_zero()
        && !limits.cancellation_timeout.is_zero()
        && !limits.close_timeout.is_zero()
}

#[cfg(test)]
mod tests {
    use super::{ClaudeLaunchProfileV1, has_reserved_argument, terminal_reason};
    use daimon_protocol::{ExecutionDispositionV1, agent::AgentTurnStopReasonV1};
    use serde_json::json;
    use std::ffi::OsString;

    #[test]
    fn reserved_transport_arguments_cannot_be_shadowed() {
        assert!(has_reserved_argument(&[OsString::from(
            "--input-format=text"
        )]));
        assert!(has_reserved_argument(&[OsString::from("--verbose")]));
        assert!(!has_reserved_argument(&[OsString::from("--model=sonnet")]));
        let _type_anchor: Option<ClaudeLaunchProfileV1> = None;
    }

    #[test]
    fn success_subtype_cannot_override_provider_error_evidence() {
        assert_eq!(
            terminal_reason(&json!({"subtype": "success", "is_error": false})),
            Some((
                ExecutionDispositionV1::Completed,
                AgentTurnStopReasonV1::EndTurn
            ))
        );
        assert_eq!(
            terminal_reason(&json!({
                "subtype": "success",
                "is_error": true,
                "errors": []
            })),
            Some((
                ExecutionDispositionV1::Failed,
                AgentTurnStopReasonV1::Failed
            ))
        );
    }
}
