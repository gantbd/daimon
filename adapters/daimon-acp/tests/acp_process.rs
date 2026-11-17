#![cfg(unix)]

use daimon_acp::{
    AcpLaunchProfileV1, AcpLimitsV1, AcpProvider, AcpWorkspaceV1, ProcessIsolationV1,
};
use daimon_host::agent::{
    AgentClientFileReader, AgentClientTerminal, AgentFileReadReceiptV1, AgentFileReadRefusalV1,
    AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1, AgentProviderReceiptV1,
    AgentProviderRecoveryV1, AgentTerminalCreateRequestV1, AgentTerminalCreatedV1,
    AgentTerminalExitV1, AgentTerminalOutputV1, AgentTerminalRefusalV1,
};
use daimon_protocol::{self as protocol, agent::*};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

fn profile() -> AgentProfileSnapshotV1 {
    AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([1; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([2; 16]),
        wire: AgentWireProfileV1::AgentClientProtocol,
        command_digest: protocol::ContentDigestV1::new([3; 32]),
        policy_digest: protocol::ContentDigestV1::new([4; 32]),
        document_digest: protocol::ContentDigestV1::new([5; 32]),
    }
}

struct NoFileReader;

impl AgentClientFileReader for NoFileReader {
    fn supports_agent_file_read(
        &self,
        _request: &AgentOpenRequestV1,
        _profile: &AgentProfileSnapshotV1,
    ) -> bool {
        false
    }

    fn read_agent_file(
        &mut self,
        _request: &daimon_host::agent::AgentFileReadRequestV1,
    ) -> Result<AgentFileReadReceiptV1, AgentFileReadRefusalV1> {
        Err(AgentFileReadRefusalV1::Denied)
    }
}

struct GovernedTerminal {
    calls: Arc<Mutex<Vec<String>>>,
}

impl AgentClientTerminal for GovernedTerminal {
    fn supports_agent_terminal(
        &self,
        request: &AgentOpenRequestV1,
        snapshot: &AgentProfileSnapshotV1,
    ) -> bool {
        assert_eq!(request.workspace, [8; 16]);
        assert_eq!(snapshot, &profile());
        true
    }

    fn create_agent_terminal(
        &mut self,
        request: &AgentTerminalCreateRequestV1,
    ) -> Result<AgentTerminalCreatedV1, AgentTerminalRefusalV1> {
        assert_eq!(request.session, protocol::AgentSessionIdV1::new([9; 16]));
        assert_eq!(request.turn, protocol::AgentTurnIdV1::new([12; 16]));
        assert_eq!(request.workspace, [8; 16]);
        assert_eq!(request.execution, execution(13, 14));
        assert_eq!(request.now, 20);
        assert_eq!(request.command, b"printf");
        assert_eq!(request.arguments, [b"ok".to_vec()]);
        assert_eq!(request.environment, [(b"MODE".to_vec(), b"test".to_vec())]);
        assert!(std::path::Path::new(std::str::from_utf8(&request.cwd).unwrap()).is_absolute());
        assert_eq!(request.output_byte_limit, Some(64));
        self.calls.lock().unwrap().push("create".to_owned());
        Ok(AgentTerminalCreatedV1 {
            terminal_id: b"governed-1".to_vec(),
        })
    }

    fn output_agent_terminal(
        &mut self,
        session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<AgentTerminalOutputV1, AgentTerminalRefusalV1> {
        assert_eq!(session, protocol::AgentSessionIdV1::new([9; 16]));
        assert_eq!(terminal_id, b"governed-1");
        self.calls.lock().unwrap().push("output".to_owned());
        Ok(AgentTerminalOutputV1 {
            output: b"ok\n".to_vec(),
            truncated: false,
            exit: Some(AgentTerminalExitV1 {
                exit_code: Some(0),
                signal: None,
            }),
        })
    }

    fn poll_agent_terminal_exit(
        &mut self,
        _session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<Option<AgentTerminalExitV1>, AgentTerminalRefusalV1> {
        assert_eq!(terminal_id, b"governed-1");
        self.calls.lock().unwrap().push("wait".to_owned());
        Ok(Some(AgentTerminalExitV1 {
            exit_code: Some(0),
            signal: None,
        }))
    }

    fn kill_agent_terminal(
        &mut self,
        _session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<(), AgentTerminalRefusalV1> {
        assert_eq!(terminal_id, b"governed-1");
        self.calls.lock().unwrap().push("kill".to_owned());
        Ok(())
    }

    fn release_agent_terminal(
        &mut self,
        _session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<(), AgentTerminalRefusalV1> {
        assert_eq!(terminal_id, b"governed-1");
        self.calls.lock().unwrap().push("release".to_owned());
        Ok(())
    }

    fn release_agent_terminals(&mut self, _session: protocol::AgentSessionIdV1) {
        self.calls.lock().unwrap().push("release_all".to_owned());
    }
}

fn governed_terminal_provider(mode: &str) -> (AcpProvider, Arc<Mutex<Vec<String>>>) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_acp_agent.sh");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let provider = AcpProvider::try_new_with_client_ports(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(2),
            slice_wait: Duration::from_millis(20),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: profile(),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![script.into_os_string(), OsString::from(mode)],
            inherited_environment_names: Vec::new(),
            agent_authentication_method: None,
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
            identity: [8; 16],
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        }],
        Box::new(NoFileReader),
        Box::new(GovernedTerminal {
            calls: Arc::clone(&calls),
        }),
    )
    .unwrap();
    (provider, calls)
}

fn execution(seed: u8, idempotency: u8) -> protocol::ExecuteRequestV1 {
    protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([seed; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [6; 16],
            task_incarnation: 1,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([7; 16]),
        profile: profile().harness_profile,
        idempotency_key: protocol::IdempotencyKeyV1::new([idempotency; 16]),
        context: Vec::new(),
        tools: Vec::new(),
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 0,
            max_context_bytes: 1_024,
            max_output_bytes: 1_024,
        },
    }
}

fn provider(mode: &str) -> AcpProvider {
    provider_with_environment(mode, Vec::new())
}

fn controlled_provider(mode: &str, control: &std::path::Path) -> AcpProvider {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_acp_agent.sh");
    AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(2),
            slice_wait: Duration::from_millis(20),
            cancellation_timeout: Duration::from_secs(2),
            close_timeout: Duration::from_secs(2),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: profile(),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                script.into_os_string(),
                OsString::from(mode),
                control.into(),
            ],
            inherited_environment_names: Vec::new(),
            agent_authentication_method: None,
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
            identity: [8; 16],
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        }],
    )
    .unwrap()
}

fn control_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("daimon-acp-{name}-{}", std::process::id()))
}

fn release_and_wait_for_emission(control: &std::path::Path) {
    let gate = control.with_extension("gate");
    let emitted = control.with_extension("emitted");
    let _ = fs::remove_file(&gate);
    let _ = fs::remove_file(&emitted);
    fs::write(&gate, []).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !emitted.exists() {
        assert!(
            Instant::now() < deadline,
            "ACP fixture did not emit terminal evidence"
        );
        thread::sleep(Duration::from_millis(5));
    }
    fs::remove_file(gate).unwrap();
    fs::remove_file(emitted).unwrap();
}

fn provider_with_agent_authentication(mode: &str, method: &str) -> AcpProvider {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_acp_agent.sh");
    AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(2),
            close_timeout: Duration::from_secs(2),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: profile(),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![script.into_os_string(), OsString::from(mode)],
            inherited_environment_names: Vec::new(),
            agent_authentication_method: Some(method.to_owned()),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
            identity: [8; 16],
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        }],
    )
    .unwrap()
}

fn provider_with_environment(
    mode: &str,
    inherited_environment_names: Vec<OsString>,
) -> AcpProvider {
    provider_with_isolation(
        mode,
        inherited_environment_names,
        ProcessIsolationV1::Direct,
    )
}

fn provider_with_isolation(
    mode: &str,
    inherited_environment_names: Vec<OsString>,
    isolation: ProcessIsolationV1,
) -> AcpProvider {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_acp_agent.sh");
    AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(2),
            slice_wait: Duration::from_millis(20),
            cancellation_timeout: Duration::from_secs(2),
            close_timeout: Duration::from_secs(2),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: profile(),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![script.into_os_string(), OsString::from(mode)],
            inherited_environment_names,
            agent_authentication_method: None,
            isolation,
        }],
        vec![AcpWorkspaceV1 {
            identity: [8; 16],
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        }],
    )
    .unwrap()
}

#[derive(Clone)]
struct GovernedFileReader {
    calls: Arc<Mutex<Vec<daimon_host::agent::AgentFileReadRequestV1>>>,
    expected_path: Vec<u8>,
    expected_now: u64,
}

impl AgentClientFileReader for GovernedFileReader {
    fn supports_agent_file_read(
        &self,
        request: &AgentOpenRequestV1,
        snapshot: &AgentProfileSnapshotV1,
    ) -> bool {
        assert_eq!(request.session, protocol::AgentSessionIdV1::new([9; 16]));
        assert_eq!(request.workspace, [8; 16]);
        assert_eq!(request.execution, execution(10, 11));
        assert_eq!(snapshot, &profile());
        true
    }

    fn read_agent_file(
        &mut self,
        request: &daimon_host::agent::AgentFileReadRequestV1,
    ) -> Result<AgentFileReadReceiptV1, AgentFileReadRefusalV1> {
        assert_eq!(request.session, protocol::AgentSessionIdV1::new([9; 16]));
        assert_eq!(request.turn, protocol::AgentTurnIdV1::new([12; 16]));
        assert_eq!(request.workspace, [8; 16]);
        assert_eq!(request.execution, execution(13, 14));
        assert_eq!(request.now, self.expected_now);
        assert_eq!(request.path, self.expected_path);
        assert_eq!(request.line, Some(1));
        assert_eq!(request.limit, Some(1));
        self.calls.lock().unwrap().push(request.clone());
        let content = b"[package]\n".to_vec();
        Ok(AgentFileReadReceiptV1 {
            path: b"Cargo.toml".to_vec(),
            content_digest: protocol::ContentDigestV1::new(Sha256::digest(&content).into()),
            content,
        })
    }
}

fn governed_file_provider(
    mode: &str,
    expected_now: u64,
) -> (
    AcpProvider,
    Arc<Mutex<Vec<daimon_host::agent::AgentFileReadRequestV1>>>,
) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_acp_agent.sh");
    let requested_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let requested_bytes = requested_path.to_str().unwrap().as_bytes().to_vec();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let provider = AcpProvider::try_new_with_file_reader(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(2),
            slice_wait: Duration::from_millis(20),
            cancellation_timeout: Duration::from_secs(2),
            close_timeout: Duration::from_secs(2),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: profile(),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                script.into_os_string(),
                OsString::from(mode),
                requested_path.into_os_string(),
            ],
            inherited_environment_names: Vec::new(),
            agent_authentication_method: None,
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
            identity: [8; 16],
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        }],
        Box::new(GovernedFileReader {
            calls: Arc::clone(&calls),
            expected_path: requested_bytes,
            expected_now,
        }),
    )
    .unwrap();
    (provider, calls)
}

#[cfg(target_os = "macos")]
#[test]
fn provider_negotiates_through_digest_bound_deny_default_seatbelt() {
    const POLICY: &str =
        "(version 1) (deny default) (allow process-exec) (allow file-read*) (allow sysctl-read)";
    let digest: [u8; 32] = Sha256::digest(POLICY.as_bytes()).into();
    let isolation = ProcessIsolationV1::macos_seatbelt(POLICY.as_bytes().to_vec(), digest).unwrap();
    let mut provider = provider_with_isolation("stream", Vec::new(), isolation);
    open(&mut provider);
}

#[test]
fn launch_diagnostics_redact_arguments_and_environment_names() {
    let launch = AcpLaunchProfileV1 {
        snapshot: profile(),
        program: PathBuf::from("/bin/sh"),
        arguments: vec![OsString::from("credential-bearing-argument")],
        inherited_environment_names: vec![OsString::from("SECRET_TOKEN_NAME")],
        agent_authentication_method: Some("credential-bearing-method".into()),
        isolation: ProcessIsolationV1::Direct,
    };
    let debug = format!("{launch:?}");
    assert!(debug.contains("<1 redacted>"));
    assert!(!debug.contains("credential-bearing-argument"));
    assert!(!debug.contains("SECRET_TOKEN_NAME"));
    assert!(!debug.contains("credential-bearing-method"));
}

#[test]
fn child_environment_is_cleared_except_for_the_exact_allowlist() {
    let mut provider = provider_with_environment("environment", vec![OsString::from("PATH")]);
    open(&mut provider);
}

#[test]
fn client_does_not_advertise_unimplemented_filesystem_or_terminal_callbacks() {
    let mut provider = provider("client_capabilities");
    open(&mut provider);
}

#[test]
fn malformed_jsonrpc_initialize_envelopes_are_refused() {
    for mode in [
        "missing_jsonrpc",
        "ambiguous_response",
        "unexpected_initialize_response",
    ] {
        let mut provider = provider(mode);
        assert_eq!(
            provider.invoke_agent(&AgentProviderInvocationV1::Open {
                request: AgentOpenRequestV1 {
                    session: protocol::AgentSessionIdV1::new([9; 16]),
                    execution: execution(10, 11),
                    workspace: [8; 16],
                    budget: AgentSessionBudgetV1 {
                        max_elapsed_millis: 10_000,
                        max_turns: 4,
                        max_events: 32,
                        max_event_bytes: 4_096,
                        max_prompt_bytes: 4_096,
                        max_permission_requests: 4,
                    },
                },
                profile: profile(),
                context: Vec::new(),
            }),
            AgentProviderOutcomeV1::OutcomeUnknown,
            "{mode}"
        );
    }
}

#[test]
fn unexpected_prompt_response_identity_is_outcome_unknown() {
    let mut provider = provider("unexpected_prompt_response");
    open(&mut provider);
    assert_eq!(
        prompt(&mut provider),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
}

#[test]
fn foreign_session_update_cannot_enter_the_local_session_event_stream() {
    let mut provider = provider("foreign_session_update");
    open(&mut provider);
    assert_eq!(
        prompt(&mut provider),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
}

#[test]
fn session_update_request_cannot_masquerade_as_a_notification() {
    let mut provider = provider("update_as_request");
    open(&mut provider);
    assert_eq!(
        prompt(&mut provider),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
}

#[test]
fn non_text_content_cannot_masquerade_as_assistant_text() {
    let mut provider = provider("non_text_with_text_field");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(completed) = prompt(&mut provider) else {
        panic!("terminal receipt expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(completed.events.len(), 1);
    assert!(matches!(
        completed.events[0].event,
        AgentEventV1::TurnFinished { .. }
    ));
}

#[test]
fn malformed_structured_updates_cannot_become_tool_or_plan_evidence() {
    let mut provider = provider("malformed_structured_updates");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(completed) = prompt(&mut provider) else {
        panic!("terminal receipt expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(completed.events.len(), 1);
    assert!(matches!(
        completed.events[0].event,
        AgentEventV1::TurnFinished { .. }
    ));
}

#[test]
fn false_and_null_agent_capabilities_are_not_promoted_to_support() {
    let mut provider = provider("false_capabilities");
    let opened = open_receipt(&mut provider);
    assert_eq!(
        opened.capabilities,
        AgentCapabilitiesV1 {
            permissions: true,
            ..AgentCapabilitiesV1::default()
        }
    );
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([92; 16]),
        })
    else {
        panic!("close receipt expected")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

#[test]
fn malformed_and_misplaced_agent_capabilities_are_not_promoted_to_support() {
    let mut provider = provider("malformed_capabilities");
    let opened = open_receipt(&mut provider);
    assert_eq!(
        opened.capabilities,
        AgentCapabilitiesV1 {
            permissions: true,
            ..AgentCapabilitiesV1::default()
        }
    );
}

#[test]
fn true_markers_and_valid_setup_states_are_preserved() {
    let mut provider = provider("advertised_capabilities");
    let opened = open_receipt(&mut provider);
    assert_eq!(
        opened.capabilities,
        AgentCapabilitiesV1 {
            load_session: true,
            resume_session: true,
            permissions: true,
            session_modes: true,
            session_models: true,
            ..AgentCapabilitiesV1::default()
        }
    );
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([93; 16]),
        })
    else {
        panic!("close receipt expected")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

#[test]
fn configured_agent_authentication_precedes_session_creation() {
    let mut provider = provider_with_agent_authentication("agent_auth", "fixture-login");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([91; 16]),
        })
    else {
        panic!("authenticated fixture did not close")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

#[test]
fn unadvertised_agent_authentication_is_refused_before_session_creation() {
    let mut provider = provider_with_agent_authentication("stream", "fixture-login");
    assert_eq!(
        provider.invoke_agent(&AgentProviderInvocationV1::Open {
            request: AgentOpenRequestV1 {
                session: protocol::AgentSessionIdV1::new([9; 16]),
                execution: execution(10, 11),
                workspace: [8; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 10_000,
                    max_turns: 4,
                    max_events: 32,
                    max_event_bytes: 4_096,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 4,
                },
            },
            profile: profile(),
            context: Vec::new(),
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
}

#[test]
fn terminal_authentication_is_never_sent_to_the_agent_connection() {
    let mut provider = provider_with_agent_authentication("terminal_auth", "fixture-login");
    assert!(matches!(
        provider.invoke_agent(&AgentProviderInvocationV1::Open {
            request: AgentOpenRequestV1 {
                session: protocol::AgentSessionIdV1::new([9; 16]),
                execution: execution(10, 11),
                workspace: [8; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 10_000,
                    max_turns: 4,
                    max_events: 32,
                    max_event_bytes: 4_096,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 4,
                },
            },
            profile: profile(),
            context: Vec::new(),
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    ));
}

#[test]
fn duplicate_authentication_method_identity_is_refused() {
    let mut provider = provider_with_agent_authentication("duplicate_auth", "fixture-login");
    assert!(matches!(
        provider.invoke_agent(&AgentProviderInvocationV1::Open {
            request: AgentOpenRequestV1 {
                session: protocol::AgentSessionIdV1::new([9; 16]),
                execution: execution(10, 11),
                workspace: [8; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 10_000,
                    max_turns: 4,
                    max_events: 32,
                    max_event_bytes: 4_096,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 4,
                },
            },
            profile: profile(),
            context: Vec::new(),
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    ));
}

#[test]
fn unsuccessful_agent_authentication_is_refused_before_session_creation() {
    let mut provider = provider_with_agent_authentication("agent_auth_error", "fixture-login");
    assert!(matches!(
        provider.invoke_agent(&AgentProviderInvocationV1::Open {
            request: AgentOpenRequestV1 {
                session: protocol::AgentSessionIdV1::new([9; 16]),
                execution: execution(10, 11),
                workspace: [8; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 10_000,
                    max_turns: 4,
                    max_events: 32,
                    max_event_bytes: 4_096,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 4,
                },
            },
            profile: profile(),
            context: Vec::new(),
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    ));
}

#[test]
fn governed_terminal_runs_the_complete_session_owned_acp_lifecycle() {
    let (mut provider, calls) = governed_terminal_provider("terminal");
    let opened = open_receipt(&mut provider);
    assert!(opened.capabilities.terminal);
    assert!(!opened.capabilities.filesystem_read);

    let AgentProviderOutcomeV1::Receipt(completed) = prompt(&mut provider) else {
        panic!("terminal-backed completion expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert!(matches!(
        &completed.events[0].event,
        AgentEventV1::Terminal { stream, bytes }
            if stream == b"combined" && bytes == b"ok\n"
    ));
    assert!(matches!(
        completed.events.last().unwrap().event,
        AgentEventV1::TurnFinished { .. }
    ));
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        ["create", "output", "wait", "kill", "release"]
    );
}

#[test]
fn cancelling_a_turn_releases_every_session_owned_terminal() {
    let (mut provider, calls) = governed_terminal_provider("terminal_cancel");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(active) = prompt(&mut provider) else {
        panic!("active terminal turn expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    let AgentProviderOutcomeV1::Receipt(cancelled) =
        provider.invoke_agent(&AgentProviderInvocationV1::Cancel {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            turn: protocol::AgentTurnIdV1::new([12; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([18; 16]),
        })
    else {
        panic!("cancel receipt expected")
    };
    assert_eq!(cancelled.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(calls.lock().unwrap().as_slice(), ["create", "release_all"]);
}

#[test]
fn idle_session_reattaches_in_a_fresh_process_without_history_replay() {
    let mut first = provider("resume");
    let opened = open_receipt(&mut first);
    assert!(opened.capabilities.resume_session);
    let recovery = opened.recovery.expect("bounded recovery locator required");
    assert_eq!(recovery.locator, b"fixture-session");
    drop(first);

    let original_open = AgentOpenRequestV1 {
        session: protocol::AgentSessionIdV1::new([9; 16]),
        execution: execution(10, 11),
        workspace: [8; 16],
        budget: AgentSessionBudgetV1 {
            max_elapsed_millis: 10_000,
            max_turns: 4,
            max_events: 32,
            max_event_bytes: 4_096,
            max_prompt_bytes: 4_096,
            max_permission_requests: 4,
        },
    };
    let mut second = provider("resume");
    let AgentProviderOutcomeV1::Receipt(reattached) =
        second.invoke_agent(&AgentProviderInvocationV1::Reattach {
            session: original_open.session,
            execution: execution(20, 21),
            original_open: Box::new(original_open),
            profile: profile(),
            context: Vec::new(),
            recovery: recovery.clone(),
            now: 30,
        })
    else {
        panic!("reattach receipt expected")
    };
    assert_eq!(reattached.phase, AgentSessionPhaseV1::Ready);
    assert!(reattached.events.is_empty());
    assert_eq!(reattached.recovery, Some(recovery));

    let AgentProviderOutcomeV1::Receipt(completed) = prompt(&mut second) else {
        panic!("resumed prompt completion expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert!(matches!(
        completed.events[0].event,
        AgentEventV1::AssistantMessage { .. }
    ));
    assert!(matches!(
        completed.events[1].event,
        AgentEventV1::TurnFinished { .. }
    ));
}

#[test]
fn failed_resume_fences_without_new_session_history_load_or_prompt_fallback() {
    let original_open = AgentOpenRequestV1 {
        session: protocol::AgentSessionIdV1::new([9; 16]),
        execution: execution(10, 11),
        workspace: [8; 16],
        budget: AgentSessionBudgetV1 {
            max_elapsed_millis: 10_000,
            max_turns: 4,
            max_events: 32,
            max_event_bytes: 4_096,
            max_prompt_bytes: 4_096,
            max_permission_requests: 4,
        },
    };
    let mut provider = provider("resume_error");
    assert_eq!(
        provider.invoke_agent(&AgentProviderInvocationV1::Reattach {
            session: original_open.session,
            execution: execution(20, 21),
            original_open: Box::new(original_open),
            profile: profile(),
            context: Vec::new(),
            recovery: AgentProviderRecoveryV1 {
                locator: b"missing-rollout".to_vec(),
            },
            now: 30,
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
}

fn open(provider: &mut AcpProvider) {
    let receipt = open_receipt(provider);
    assert_eq!(receipt.phase, AgentSessionPhaseV1::Ready);
}

fn open_receipt(provider: &mut AcpProvider) -> AgentProviderReceiptV1 {
    let outcome = provider.invoke_agent(&AgentProviderInvocationV1::Open {
        request: AgentOpenRequestV1 {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            execution: execution(10, 11),
            workspace: [8; 16],
            budget: AgentSessionBudgetV1 {
                max_elapsed_millis: 10_000,
                max_turns: 4,
                max_events: 32,
                max_event_bytes: 4_096,
                max_prompt_bytes: 4_096,
                max_permission_requests: 4,
            },
        },
        profile: profile(),
        context: Vec::new(),
    });
    let AgentProviderOutcomeV1::Receipt(receipt) = outcome else {
        panic!("open receipt expected")
    };
    receipt
}

fn prompt(provider: &mut AcpProvider) -> AgentProviderOutcomeV1 {
    let bytes = b"inspect the boundary".to_vec();
    provider.invoke_agent(&AgentProviderInvocationV1::Prompt {
        request: AgentTurnRequestV1 {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            turn: protocol::AgentTurnIdV1::new([12; 16]),
            expected_revision: 1,
            execution: execution(13, 14),
            prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&bytes).into()),
            prompt: bytes,
        },
        profile: profile(),
        context: Vec::new(),
        now: 20,
    })
}

#[test]
fn governed_client_file_read_preserves_canonical_binding_and_digest_evidence() {
    let (mut provider, calls) = governed_file_provider("file_read", 20);
    let opened = open_receipt(&mut provider);
    assert!(opened.capabilities.filesystem_read);
    assert!(!opened.capabilities.filesystem_write);
    assert!(!opened.capabilities.terminal);

    let AgentProviderOutcomeV1::Receipt(completed) = prompt(&mut provider) else {
        panic!("file-grounded completion expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(calls.lock().unwrap().len(), 1);
    let content = b"[package]\n";
    assert!(matches!(
        &completed.events[0].event,
        AgentEventV1::FileRead {
            path,
            content_digest,
            content_bytes: 10,
        } if path == b"Cargo.toml"
            && *content_digest == protocol::ContentDigestV1::new(Sha256::digest(content).into())
    ));
    assert!(matches!(
        completed.events[1].event,
        AgentEventV1::AssistantMessage { .. }
    ));
    assert!(matches!(
        completed.events[2].event,
        AgentEventV1::TurnFinished { .. }
    ));
}

#[test]
fn delayed_file_read_uses_the_advance_logical_time() {
    let (mut provider, calls) = governed_file_provider("file_read_delayed", 99);
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(active) = prompt(&mut provider) else {
        panic!("active slice expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    assert!(calls.lock().unwrap().is_empty());
    thread::sleep(Duration::from_millis(100));
    let AgentProviderOutcomeV1::Receipt(completed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Advance {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            turn: protocol::AgentTurnIdV1::new([12; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([24; 16]),
            now: 99,
        })
    else {
        panic!("file-grounded continuation expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert!(matches!(
        completed.events[0].event,
        AgentEventV1::FileRead { .. }
    ));
}

#[test]
fn real_stdio_process_streams_bounded_progress_then_terminal_evidence() {
    let control = control_path("stream");
    let mut provider = controlled_provider("controlled_stream", &control);
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(first) = prompt(&mut provider) else {
        panic!("first progress slice expected")
    };
    assert_eq!(first.phase, AgentSessionPhaseV1::TurnActive);
    assert!(matches!(
        first.events[0].event,
        AgentEventV1::AssistantMessage { .. }
    ));
    release_and_wait_for_emission(&control);
    let AgentProviderOutcomeV1::Receipt(second) =
        provider.invoke_agent(&AgentProviderInvocationV1::Advance {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            turn: protocol::AgentTurnIdV1::new([12; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([15; 16]),
            now: 21,
        })
    else {
        panic!("terminal slice expected")
    };
    assert_eq!(second.phase, AgentSessionPhaseV1::Ready);
    assert!(matches!(
        second.events.last().unwrap().event,
        AgentEventV1::TurnFinished { .. }
    ));
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([19; 16]),
        })
    else {
        panic!("close receipt expected")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

#[test]
fn permission_selection_uses_exact_correlated_option() {
    let mut provider = provider("permission");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(waiting) = prompt(&mut provider) else {
        panic!("permission slice expected")
    };
    let AgentEventV1::Permission(permission) = &waiting.events[0].event else {
        panic!("typed permission expected")
    };
    let allow = permission
        .options
        .iter()
        .find(|option| option.kind == AgentPermissionOptionKindV1::AllowOnce)
        .unwrap();
    let AgentProviderOutcomeV1::Receipt(completed) =
        provider.invoke_agent(&AgentProviderInvocationV1::DecidePermission {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            execution: execution(16, 17),
            decision: AgentPermissionDecisionV1 {
                request: permission.request,
                option: allow.id,
            },
            now: 22,
        })
    else {
        panic!("permission continuation expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
}

#[test]
fn stale_permission_request_and_option_do_not_consume_the_retained_challenge() {
    let mut provider = provider("permission");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(waiting) = prompt(&mut provider) else {
        panic!("permission slice expected")
    };
    let AgentEventV1::Permission(permission) = &waiting.events[0].event else {
        panic!("typed permission expected")
    };
    let allow = permission
        .options
        .iter()
        .find(|option| option.kind == AgentPermissionOptionKindV1::AllowOnce)
        .unwrap();
    assert_eq!(
        provider.invoke_agent(&AgentProviderInvocationV1::DecidePermission {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            execution: execution(16, 17),
            decision: AgentPermissionDecisionV1 {
                request: protocol::AgentPermissionRequestIdV1::new([98; 16]),
                option: allow.id,
            },
            now: 22,
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
    assert_eq!(
        provider.invoke_agent(&AgentProviderInvocationV1::DecidePermission {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            execution: execution(16, 17),
            decision: AgentPermissionDecisionV1 {
                request: permission.request,
                option: protocol::AgentPermissionOptionIdV1::new([99; 16]),
            },
            now: 22,
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
    let AgentProviderOutcomeV1::Receipt(completed) =
        provider.invoke_agent(&AgentProviderInvocationV1::DecidePermission {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            execution: execution(16, 17),
            decision: AgentPermissionDecisionV1 {
                request: permission.request,
                option: allow.id,
            },
            now: 22,
        })
    else {
        panic!("retained permission continuation expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
}

#[test]
fn provider_exit_after_prompt_dispatch_is_uncertain_and_never_reopened_by_advance() {
    let mut provider = provider("exit_after_prompt");
    open(&mut provider);
    assert_eq!(
        prompt(&mut provider),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
    assert_eq!(
        provider.invoke_agent(&AgentProviderInvocationV1::Advance {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            turn: protocol::AgentTurnIdV1::new([12; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([15; 16]),
            now: 23,
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
}

#[test]
fn cancellation_is_sent_while_original_prompt_remains_pending() {
    let mut provider = provider("cancel");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(active) = prompt(&mut provider) else {
        panic!("active slice expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    let AgentProviderOutcomeV1::Receipt(cancelled) =
        provider.invoke_agent(&AgentProviderInvocationV1::Cancel {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            turn: protocol::AgentTurnIdV1::new([12; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([18; 16]),
        })
    else {
        panic!("cancel receipt expected")
    };
    assert!(matches!(
        cancelled.events.last().unwrap().event,
        AgentEventV1::TurnFinished {
            disposition: protocol::ExecutionDispositionV1::Cancelled,
            ..
        }
    ));
}

#[test]
fn completion_winning_the_cancel_race_is_not_rewritten_as_cancelled() {
    let control = control_path("cancel-race");
    let mut provider = controlled_provider("controlled_cancel_race", &control);
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(active) = prompt(&mut provider) else {
        panic!("active slice expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    release_and_wait_for_emission(&control);
    let AgentProviderOutcomeV1::Receipt(completed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Cancel {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            turn: protocol::AgentTurnIdV1::new([12; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([18; 16]),
        })
    else {
        panic!("completion evidence expected")
    };
    assert!(matches!(
        completed.events.last().unwrap().event,
        AgentEventV1::TurnFinished {
            disposition: protocol::ExecutionDispositionV1::Completed,
            stop_reason: AgentTurnStopReasonV1::EndTurn,
            ..
        }
    ));
}

#[test]
fn silent_live_prompt_is_empty_active_observation_not_uncertainty() {
    let mut provider = provider("silent");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(active) = prompt(&mut provider) else {
        panic!("active observation expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    assert!(active.events.is_empty());
}

#[test]
fn verified_ambient_context_is_projected_as_distinct_bounded_content() {
    let mut provider = provider("context");
    open(&mut provider);
    let bytes = b"use the evidence".to_vec();
    let AgentProviderOutcomeV1::Receipt(completed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Prompt {
            request: AgentTurnRequestV1 {
                session: protocol::AgentSessionIdV1::new([9; 16]),
                turn: protocol::AgentTurnIdV1::new([12; 16]),
                expected_revision: 1,
                execution: execution(13, 14),
                prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&bytes).into()),
                prompt: bytes,
            },
            profile: profile(),
            context: vec![protocol::ContextEvidenceV1 {
                reference: protocol::ContextReferenceIdV1::new([20; 16]),
                kind: protocol::ContextKindV1::DendriteGrounding,
                bytes: b"ambient expertise".to_vec(),
                source_digest: protocol::ContentDigestV1::new([21; 32]),
                grounding: Some(protocol::GroundingEvidenceV1 {
                    depth: protocol::GroundingDepthV1::Ambient,
                    grounding_digest: protocol::ContentDigestV1::new([22; 32]),
                    surface_digest: protocol::ContentDigestV1::new([23; 32]),
                }),
            }],
            now: 20,
        })
    else {
        panic!("grounded completion expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert!(matches!(
        completed.events[0].event,
        AgentEventV1::AssistantMessage { .. }
    ));
}
