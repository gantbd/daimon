#![cfg(unix)]

use aegis_authority::{EngineId, Limits as AegisLimits, PrincipalId, SessionId};
use aegis_local_daemon::unix::{Authenticator as AegisAuthenticator, Daemon as AegisDaemon};
use aegis_service::{
    AuthenticatedSessionV1 as AegisSessionV1, Service as AegisService,
    ServiceLimitsV1 as AegisServiceLimitsV1,
};
use daimon_client::{AgentReadOnlyClient, AgentSessionClient};
use daimon_protocol::{self as protocol, agent::*};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
static PROCESS_JOURNEY: Mutex<()> = Mutex::new(());

struct AegisAuthentication;

impl AegisAuthenticator for AegisAuthentication {
    type Error = Infallible;

    fn authenticate(&mut self, _: &UnixStream) -> Result<AegisSessionV1, Self::Error> {
        Ok(AegisSessionV1 {
            principal: PrincipalId::new([1; 16]),
            session: SessionId::new([9; 16]),
            administrator: true,
        })
    }
}

struct Fixture {
    root: PathBuf,
    aegis_socket: PathBuf,
    chronos_socket: PathBuf,
    agent_socket: PathBuf,
    store: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "daimon-local-agent-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self {
            aegis_socket: root.join("aegis.sock"),
            chronos_socket: root.join("chronos.sock"),
            agent_socket: root.join("agent.sock"),
            store: root.join("store"),
            config: root.join("agent.json"),
            root,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.aegis_socket);
        let _ = fs::remove_file(&self.chronos_socket);
        let _ = fs::remove_file(&self.agent_socket);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn start_aegis(fixture: &Fixture, request_count: usize) -> thread::JoinHandle<()> {
    let authority_id = EngineId::new([8; 16]);
    let authority = aegis_local::create_new(
        fixture.root.join("authority"),
        authority_id,
        AegisLimits::default(),
    )
    .unwrap();
    let service =
        AegisService::new(authority, authority_id, AegisServiceLimitsV1::default()).unwrap();
    let mut daemon = AegisDaemon::bind_new(
        &fixture.aegis_socket,
        service,
        AegisAuthentication,
        aegis_wire::LimitsV1::default(),
        // The terminal-boundary qualification deliberately keeps this authority
        // connection open while a real child process runs. Hosted macOS runners
        // can take just over three seconds there, so the fixture must not turn a
        // healthy idle interval into a synthetic transport failure.
        Duration::from_secs(15),
        16,
    )
    .unwrap();
    thread::spawn(move || {
        for _ in 0..request_count {
            daemon.serve_next().unwrap();
        }
    })
}

fn start_chronos(fixture: &Fixture) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(&fixture.chronos_socket).unwrap();
    let limits = chronos_limits();
    thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            BufReader::new(stream.try_clone().unwrap())
                .take((limits.max_frame_bytes + 1) as u64)
                .read_until(b'\n', &mut request)
                .unwrap();
            assert_eq!(request.pop(), Some(b'\n'));
            let request = chronos_wire::decode_request(&request, limits).unwrap();
            assert!(matches!(
                request.command,
                chronos_protocol::Command::Snapshot { ref task } if task == "local-agent-task"
            ));
            let response = chronos_protocol::Response {
                version: 1,
                outcome: chronos_protocol::Outcome::Snapshot {
                    value: Some(chronos_protocol::Entry {
                        reference: chronos_protocol::Reference {
                            task: "local-agent-task".to_owned(),
                            incarnation: "1".to_owned(),
                        },
                        snapshot: chronos_protocol::Snapshot {
                            phase: chronos_protocol::Phase::Running,
                            attempt_number: Some(1),
                            dependency_count: 0,
                            required_capability_count: 0,
                            priority: 0,
                            max_attempts: 1,
                        },
                    }),
                    revision: Some(chronos_protocol::Revision::Finite("1".to_owned())),
                },
            };
            let response = chronos_wire::encode(&response, limits.max_frame_bytes).unwrap();
            stream.write_all(&response).unwrap();
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();
        }
    })
}

fn chronos_limits() -> chronos_protocol::Limits {
    chronos_protocol::Limits {
        max_frame_bytes: 1024 * 1024,
        max_id_bytes: 256,
        max_graph_tasks: 1024,
        max_dependencies_per_task: 128,
        max_capabilities_per_task: 64,
        max_capability_bytes: 256,
        max_page_entries: 256,
    }
}

fn write_config(fixture: &Fixture) {
    let readable = fixture.root.join("grounding.txt");
    fs::write(&readable, b"[package]\nsecond line\n").unwrap();
    let terminal_boundary = std::env::var_os("DAIMON_PROCESS_BOUNDARY")
        .map(PathBuf::from)
        .map(fs::canonicalize)
        .transpose()
        .unwrap();
    let terminal_enabled = terminal_boundary.is_some();
    let acp_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../adapters/daimon-acp/tests/support/fake_acp_agent.sh")
        .canonicalize()
        .unwrap();
    let (mode, provider_arguments, isolation) = if cfg!(target_os = "macos") {
        let policy = "(version 1) (deny default) (allow process-exec) (allow process-fork) (allow file-read*) (allow sysctl-read)";
        let policy_path = fixture.root.join("provider.sb");
        fs::write(&policy_path, policy).unwrap();
        let digest = Sha256::digest(policy.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mode = if terminal_enabled {
            "sandbox_terminal"
        } else {
            "sandbox_file_read"
        };
        let fixture_path = if terminal_enabled {
            fixture.root.clone()
        } else {
            readable.clone()
        };
        (
            mode,
            serde_json::json!([
                acp_fixture,
                mode,
                fixture.root.join("forbidden"),
                fixture_path
            ]),
            serde_json::json!({
                "kind": "macos_seatbelt",
                "policy_path": policy_path,
                "policy_digest": format!("sha256:{digest}")
            }),
        )
    } else {
        let mode = if terminal_enabled {
            "terminal"
        } else {
            "file_read"
        };
        let fixture_path = if terminal_enabled {
            fixture.root.clone()
        } else {
            readable.clone()
        };
        (
            mode,
            serde_json::json!([acp_fixture, mode, fixture_path]),
            serde_json::json!({"kind": "direct"}),
        )
    };
    let acp_file_read = (!terminal_enabled).then(|| {
        serde_json::json!({
            "capability": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "paths": ["grounding.txt"],
            "max_bytes": 4096
        })
    });
    let acp_terminal = terminal_boundary.map(|boundary_program| {
        serde_json::json!({
            "capability": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "boundary_program": boundary_program,
            "commands": [{
                "command": "printf",
                "program": "/usr/bin/printf",
                "argument_prefix": ["ok"]
            }],
            "environment_names": ["MODE"],
            "max_handles": 1,
            "max_output_bytes": 64
        })
    });
    let value = serde_json::json!({
        "principal": "01010101010101010101010101010101",
        "aegis_socket": fixture.aegis_socket,
        "aegis_expected_epoch": 0,
        "aegis_grant_now": 1,
        "aegis_grant_expires_at": 1000,
        "chronos_socket": fixture.chronos_socket,
        "daimon_socket": fixture.agent_socket,
        "store_directory": fixture.store,
        "providers": [{
            "provider_id": "02020202020202020202020202020202",
            "harness_profile_id": "03030303030303030303030303030303",
            "policy_digest": format!("sha256:{}", "22".repeat(32)),
            "program": "/bin/sh",
            "arguments": provider_arguments,
            "inherited_environment_names": [],
            "isolation": isolation,
            "transport": "acp"
        }],
        "workspaces": [{
            "identity": "06060606060606060606060606060606",
            "path": fixture.root,
            "acp_file_read": acp_file_read,
            "acp_terminal": acp_terminal
        }],
        "task_bindings": [{
            "external_task_key": "07070707070707070707070707070707",
            "chronos_task_id": "local-agent-task"
        }],
        "tool_capabilities": ["0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"],
        "context": [],
        "io_timeout_ms": 3000,
        "max_agent_sessions": 8,
        "max_service_sessions": 4,
        "max_requests_per_connection": 16,
        "max_store_bytes": 1048576,
        "max_context_bytes": 4096
    });
    assert_eq!(mode.starts_with("sandbox_"), cfg!(target_os = "macos"));
    fs::write(&fixture.config, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

fn write_resume_config(fixture: &Fixture) {
    let acp_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../adapters/daimon-acp/tests/support/fake_acp_agent.sh")
        .canonicalize()
        .unwrap();
    let value = serde_json::json!({
        "principal": "01010101010101010101010101010101",
        "aegis_socket": fixture.aegis_socket,
        "aegis_expected_epoch": 0,
        "aegis_grant_now": 1,
        "aegis_grant_expires_at": 1000,
        "chronos_socket": fixture.chronos_socket,
        "daimon_socket": fixture.agent_socket,
        "store_directory": fixture.store,
        "providers": [{
            "provider_id": "02020202020202020202020202020202",
            "harness_profile_id": "03030303030303030303030303030303",
            "policy_digest": format!("sha256:{}", "22".repeat(32)),
            "program": "/bin/sh",
            "arguments": [acp_fixture, "resume"],
            "inherited_environment_names": [],
            "isolation": {"kind": "direct"},
            "transport": "acp"
        }],
        "workspaces": [{
            "identity": "06060606060606060606060606060606",
            "path": fixture.root
        }],
        "task_bindings": [{
            "external_task_key": "07070707070707070707070707070707",
            "chronos_task_id": "local-agent-task"
        }],
        "tool_capabilities": ["0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"],
        "context": [],
        "io_timeout_ms": 3000,
        "max_agent_sessions": 8,
        "max_service_sessions": 4,
        "max_requests_per_connection": 16,
        "max_store_bytes": 1048576,
        "max_context_bytes": 4096
    });
    fs::write(&fixture.config, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

#[test]
fn executable_projects_validated_provider_catalog_without_launch_material() {
    let _journey = PROCESS_JOURNEY.lock().unwrap();
    let fixture = Fixture::new();
    write_config(&fixture);
    let output = Command::new(env!("CARGO_BIN_EXE_daimon-local-agent"))
        .arg("--describe-providers")
        .arg(&fixture.config)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let catalog: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(catalog["version"], 1);
    assert_eq!(catalog["owner"], "daimon-local-agent");
    assert_eq!(catalog["providers"].as_array().unwrap().len(), 1);
    assert_eq!(catalog["providers"][0]["transport"], "acp");
    assert_eq!(catalog["providers"][0]["executable_available"], true);
    let projection = String::from_utf8(output.stdout).unwrap();
    assert!(!projection.contains("/bin/sh"));
    assert!(!projection.contains(fixture.root.to_str().unwrap()));
    assert!(!projection.contains("inherited_environment_names"));
    assert!(!projection.contains("arguments"));
}

#[test]
fn executable_plans_applies_and_replays_guarded_provider_edit() {
    let _journey = PROCESS_JOURNEY.lock().unwrap();
    let fixture = Fixture::new();
    write_config(&fixture);
    let catalog_output = Command::new(env!("CARGO_BIN_EXE_daimon-local-agent"))
        .arg("--describe-providers")
        .arg(&fixture.config)
        .output()
        .unwrap();
    assert!(catalog_output.status.success());
    let catalog: serde_json::Value = serde_json::from_slice(&catalog_output.stdout).unwrap();
    let original_digest = catalog["document_digest"].as_str().unwrap();
    let owner_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.config).unwrap()).unwrap();
    let mut provider = owner_document["providers"][0].clone();
    provider["policy_digest"] = serde_json::Value::String(format!("sha256:{}", "77".repeat(32)));
    let operation_id = "abababababababababababababababab";
    let plan_request = serde_json::json!({
        "version": 1,
        "operation_id": operation_id,
        "expected_document_digest": original_digest,
        "provider": provider
    });
    let plan_output = run_provider_edit(&fixture, "--plan-provider-edit", &plan_request);
    assert!(plan_output.status.success(), "{:?}", plan_output.stderr);
    let plan: serde_json::Value = serde_json::from_slice(&plan_output.stdout).unwrap();
    assert_eq!(plan["owner"], "daimon-local-agent");
    assert_eq!(plan["action"], "replace");
    assert_eq!(plan["changed_fields"], serde_json::json!(["policy_digest"]));
    assert_eq!(plan["restart_required"], true);
    let projection = String::from_utf8(plan_output.stdout).unwrap();
    assert!(!projection.contains("/bin/sh"));
    assert!(!projection.contains(fixture.root.to_str().unwrap()));
    assert!(!projection.contains("fake_acp_agent"));

    let apply_request = serde_json::json!({
        "version": 1,
        "operation_id": operation_id,
        "expected_document_digest": original_digest,
        "expected_plan_digest": plan["plan_digest"],
        "expected_candidate_document_digest": plan["candidate_document_digest"],
        "provider": plan_request["provider"]
    });
    let apply_output = run_provider_edit(&fixture, "--apply-provider-edit", &apply_request);
    assert!(apply_output.status.success(), "{:?}", apply_output.stderr);
    let receipt: serde_json::Value = serde_json::from_slice(&apply_output.stdout).unwrap();
    assert_eq!(receipt["disposition"], "applied");
    assert_eq!(receipt["replayed"], false);
    assert_eq!(
        receipt["document_digest"],
        plan["candidate_document_digest"]
    );

    let replay_output = run_provider_edit(&fixture, "--apply-provider-edit", &apply_request);
    assert!(replay_output.status.success(), "{:?}", replay_output.stderr);
    let replay: serde_json::Value = serde_json::from_slice(&replay_output.stdout).unwrap();
    assert_eq!(replay["disposition"], "already_applied");
    assert_eq!(replay["replayed"], true);

    let no_change_request = serde_json::json!({
        "version": 1,
        "operation_id": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "expected_document_digest": plan["candidate_document_digest"],
        "provider": plan_request["provider"]
    });
    let no_change_output = run_provider_edit(&fixture, "--plan-provider-edit", &no_change_request);
    assert!(!no_change_output.status.success());
    assert!(
        String::from_utf8(no_change_output.stderr)
            .unwrap()
            .contains("no apply is needed")
    );

    let stale_output = run_provider_edit(&fixture, "--plan-provider-edit", &plan_request);
    assert!(!stale_output.status.success());
    assert!(
        String::from_utf8(stale_output.stderr)
            .unwrap()
            .contains("changed; refresh")
    );
    let final_catalog_output = Command::new(env!("CARGO_BIN_EXE_daimon-local-agent"))
        .arg("--describe-providers")
        .arg(&fixture.config)
        .output()
        .unwrap();
    let final_catalog: serde_json::Value =
        serde_json::from_slice(&final_catalog_output.stdout).unwrap();
    assert_eq!(
        final_catalog["document_digest"],
        plan["candidate_document_digest"]
    );
    assert_eq!(
        final_catalog["providers"][0]["policy_digest"],
        format!("sha256:{}", "77".repeat(32))
    );
}

fn run_provider_edit(
    fixture: &Fixture,
    command: &str,
    request: &serde_json::Value,
) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_daimon-local-agent"))
        .arg(command)
        .arg(&fixture.config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(request).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn start_agent(fixture: &Fixture) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_daimon-local-agent"))
        .arg("--supervised")
        .arg(&fixture.config)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    wait_for_socket(&fixture.agent_socket, Duration::from_secs(5));
    child
}

fn stop_agent(child: &mut Child, socket: &Path) {
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "supervised agent shutdown failed: {status}"
    );
    assert!(!socket.exists(), "supervised agent retained its socket");
}

fn wait_for_socket(path: &Path, timeout: Duration) {
    let started = Instant::now();
    while !path.exists() {
        assert!(started.elapsed() < timeout, "socket was not created");
        thread::sleep(Duration::from_millis(10));
    }
}

fn execution(seed: u8, idempotency: u8) -> protocol::ExecuteRequestV1 {
    protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([seed; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [7; 16],
            task_incarnation: 1,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([1; 16]),
        profile: protocol::HarnessProfileIdV1::new([3; 16]),
        idempotency_key: protocol::IdempotencyKeyV1::new([idempotency; 16]),
        context: Vec::new(),
        tools: vec![protocol::ToolCapabilityIdV1::new([10; 16])],
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: 5_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 1,
            max_context_bytes: 4_096,
            max_output_bytes: 4_096,
        },
    }
}

#[test]
fn executable_crosses_authority_attempt_provider_and_durable_reopen() {
    let _journey = PROCESS_JOURNEY.lock().unwrap();
    let fixture = Fixture::new();
    let aegis = start_aegis(&fixture, 2);
    let chronos = start_chronos(&fixture);
    write_config(&fixture);
    let mut first = start_agent(&fixture);

    let (service_session, port) = daimon_client::unix::connect_agent(
        &fixture.agent_socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut client = AgentSessionClient::new(service_session, port);
    let agent_session = protocol::AgentSessionIdV1::new([11; 16]);
    let open_reply = client
        .open(
            AgentOpenRequestV1 {
                session: agent_session,
                execution: execution(12, 13),
                workspace: [6; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 10_000,
                    max_turns: 2,
                    max_events: 32,
                    max_event_bytes: 4_096,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 0,
                },
            },
            10,
        )
        .unwrap();
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(opened)) = open_reply else {
        panic!("agent open expected, received {open_reply:?}")
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    let turn = protocol::AgentTurnIdV1::new([14; 16]);
    let prompt = b"return bounded fixture output".to_vec();
    let prompt_reply = client
        .prompt(
            AgentTurnRequestV1 {
                session: agent_session,
                turn,
                expected_revision: opened.revision,
                execution: execution(15, 16),
                prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&prompt).into()),
                prompt,
            },
            11,
        )
        .unwrap();
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(mut view)) = prompt_reply else {
        panic!("agent prompt expected, received {prompt_reply:?}")
    };
    for seed in 20_u8..40 {
        if view.phase == AgentSessionPhaseV1::Ready {
            break;
        }
        thread::sleep(Duration::from_millis(20));
        let AgentReplyV1::Accepted(AgentOutcomeV1::Session(next)) = client
            .advance(
                agent_session,
                turn,
                view.revision,
                protocol::IdempotencyKeyV1::new([seed; 16]),
                12,
            )
            .unwrap()
        else {
            panic!("agent advance expected")
        };
        view = next;
    }
    assert_eq!(view.phase, AgentSessionPhaseV1::Ready);
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(closed)) = client
        .close(
            agent_session,
            view.revision,
            protocol::IdempotencyKeyV1::new([41; 16]),
            13,
        )
        .unwrap()
    else {
        panic!("agent close expected")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
    drop(client);
    stop_agent(&mut first, &fixture.agent_socket);

    let mut second = start_agent(&fixture);
    let (service_session, port) = daimon_client::unix::connect_agent(
        &fixture.agent_socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut reader = AgentReadOnlyClient::new(service_session, port);
    let reopened = reader.current_view(agent_session).unwrap();
    assert_eq!(reopened.phase, AgentSessionPhaseV1::Closed);
    assert_eq!(reopened.revision, closed.revision);
    let events = reader.event_page(agent_session, None, 32).unwrap();
    if std::env::var_os("DAIMON_PROCESS_BOUNDARY").is_some() {
        assert!(events.entries.iter().any(|event| matches!(
            &event.event,
            AgentEventV1::Terminal { stream, bytes }
                if stream == b"combined" && bytes == b"ok"
        )));
    } else {
        assert!(events.entries.iter().any(|event| matches!(
            &event.event,
            AgentEventV1::FileRead {
                path,
                content_bytes: 10,
                ..
            } if path == b"grounding.txt"
        )));
        assert!(events.entries.iter().any(|event| matches!(
            &event.event,
            AgentEventV1::AssistantMessage { bytes } if bytes == b"file grounded"
        )));
    }
    assert!(events.entries.iter().any(|event| matches!(
        event.event,
        AgentEventV1::TurnFinished {
            stop_reason: AgentTurnStopReasonV1::EndTurn,
            ..
        }
    )));
    drop(reader);
    stop_agent(&mut second, &fixture.agent_socket);

    chronos.join().unwrap();
    aegis.join().unwrap();
}

#[test]
fn executable_restarts_idle_acp_session_and_requires_explicit_reattach() {
    let _journey = PROCESS_JOURNEY.lock().unwrap();
    let fixture = Fixture::new();
    let aegis = start_aegis(&fixture, 2);
    let chronos = start_chronos(&fixture);
    write_resume_config(&fixture);
    let mut first = start_agent(&fixture);

    let (service_session, port) = daimon_client::unix::connect_agent(
        &fixture.agent_socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut client = AgentSessionClient::new(service_session, port);
    let agent_session = protocol::AgentSessionIdV1::new([51; 16]);
    let open_reply = client
        .open(
            AgentOpenRequestV1 {
                session: agent_session,
                execution: execution(52, 53),
                workspace: [6; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 10_000,
                    max_turns: 2,
                    max_events: 32,
                    max_event_bytes: 4_096,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 0,
                },
            },
            10,
        )
        .unwrap();
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(opened)) = open_reply else {
        panic!("resumable agent open expected, received {open_reply:?}")
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    assert!(opened.capabilities.resume_session);
    assert!(opened.active_turn.is_none());
    drop(client);
    stop_agent(&mut first, &fixture.agent_socket);

    let mut second = start_agent(&fixture);
    let (service_session, port) = daimon_client::unix::connect_agent(
        &fixture.agent_socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut reader = AgentReadOnlyClient::new(service_session, port);
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(detached)) =
        reader.inspect(agent_session).unwrap()
    else {
        panic!("detached agent session expected")
    };
    assert_eq!(detached.phase, AgentSessionPhaseV1::ReattachRequired);
    assert_eq!(detached.revision, opened.revision);
    assert!(detached.active_turn.is_none());
    drop(reader);

    let (service_session, port) = daimon_client::unix::connect_agent(
        &fixture.agent_socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut client = AgentSessionClient::new(service_session, port);

    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(ready)) = client
        .reattach(agent_session, detached.revision, execution(54, 55), 20)
        .unwrap()
    else {
        panic!("explicit reattach expected")
    };
    assert_eq!(ready.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(ready.revision, detached.revision + 1);
    drop(client);

    let (service_session, port) = daimon_client::unix::connect_agent(
        &fixture.agent_socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut reader = AgentReadOnlyClient::new(service_session, port);
    let events = reader.event_page(agent_session, None, 32).unwrap();
    assert!(
        events.entries.is_empty(),
        "reattach must not replay history"
    );
    drop(reader);

    let prompt = b"continue only after explicit reattach".to_vec();
    let turn = protocol::AgentTurnIdV1::new([56; 16]);
    let (service_session, port) = daimon_client::unix::connect_agent(
        &fixture.agent_socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut client = AgentSessionClient::new(service_session, port);
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(mut view)) = client
        .prompt(
            AgentTurnRequestV1 {
                session: agent_session,
                turn,
                expected_revision: ready.revision,
                execution: execution(57, 58),
                prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&prompt).into()),
                prompt,
            },
            21,
        )
        .unwrap()
    else {
        panic!("post-reattach prompt expected")
    };
    for seed in 60_u8..80 {
        if view.phase == AgentSessionPhaseV1::Ready {
            break;
        }
        thread::sleep(Duration::from_millis(20));
        let AgentReplyV1::Accepted(AgentOutcomeV1::Session(next)) = client
            .advance(
                agent_session,
                turn,
                view.revision,
                protocol::IdempotencyKeyV1::new([seed; 16]),
                22,
            )
            .unwrap()
        else {
            panic!("post-reattach advance expected")
        };
        view = next;
    }
    assert_eq!(view.phase, AgentSessionPhaseV1::Ready);
    drop(client);

    let (service_session, port) = daimon_client::unix::connect_agent(
        &fixture.agent_socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut reader = AgentReadOnlyClient::new(service_session, port);
    let events = reader.event_page(agent_session, None, 32).unwrap();
    assert!(events.entries.iter().any(|event| matches!(
        &event.event,
        AgentEventV1::AssistantMessage { bytes } if bytes == b"resumed session"
    )));
    assert!(events.entries.iter().any(|event| matches!(
        event.event,
        AgentEventV1::TurnFinished {
            stop_reason: AgentTurnStopReasonV1::EndTurn,
            ..
        }
    )));
    drop(reader);
    stop_agent(&mut second, &fixture.agent_socket);

    chronos.join().unwrap();
    aegis.join().unwrap();
}
