#![cfg(unix)]

use daimon_acp::{
    AcpLaunchProfileV1, AcpLimitsV1, AcpProvider, AcpWorkspaceV1, ProcessIsolationV1,
};
use daimon_agent_router::{AgentProviderRouteV1, AgentProviderRouter};
use daimon_claude::{ClaudeLaunchProfileV1, ClaudeLimitsV1, ClaudeProvider, ClaudeWorkspaceV1};
use daimon_host::agent::{AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1};
use daimon_protocol::{self as protocol, agent::*};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, fs, path::PathBuf, time::Duration};

struct LiveWorkspace(PathBuf);

impl LiveWorkspace {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "daimon-live-provider-router-{}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for LiveWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn profile(seed: u8, wire: AgentWireProfileV1) -> AgentProfileSnapshotV1 {
    AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([seed; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([seed + 1; 16]),
        wire,
        command_digest: protocol::ContentDigestV1::new([seed + 2; 32]),
        policy_digest: protocol::ContentDigestV1::new([seed + 3; 32]),
        document_digest: protocol::ContentDigestV1::new([seed + 4; 32]),
    }
}

fn environment(name: &str, fallback: &str) -> Vec<OsString> {
    std::env::var(name)
        .unwrap_or_else(|_| fallback.to_owned())
        .split_whitespace()
        .map(OsString::from)
        .collect()
}

fn arguments(name: &str) -> Vec<OsString> {
    std::env::var(name)
        .unwrap_or_default()
        .split_whitespace()
        .map(OsString::from)
        .collect()
}

fn execution(profile: &AgentProfileSnapshotV1, seed: u8) -> protocol::ExecuteRequestV1 {
    protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([seed; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [90; 16],
            task_incarnation: 1,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([91; 16]),
        profile: profile.harness_profile,
        idempotency_key: protocol::IdempotencyKeyV1::new([seed + 1; 16]),
        context: Vec::new(),
        tools: Vec::new(),
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: 30_000,
            max_input_tokens: 1,
            max_output_tokens: 1,
            max_tool_calls: 0,
            max_context_bytes: 1_024,
            max_output_bytes: 1_024,
        },
    }
}

fn open(
    router: &mut AgentProviderRouter,
    session: protocol::AgentSessionIdV1,
    profile: &AgentProfileSnapshotV1,
    workspace: [u8; 16],
    seed: u8,
) {
    let AgentProviderOutcomeV1::Receipt(receipt) =
        router.invoke_agent(&AgentProviderInvocationV1::Open {
            request: AgentOpenRequestV1 {
                session,
                execution: execution(profile, seed),
                workspace,
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 120_000,
                    max_turns: 1,
                    max_events: 128,
                    max_event_bytes: 64 * 1024,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 1,
                },
            },
            profile: profile.clone(),
            context: Vec::new(),
        })
    else {
        panic!("live provider did not open through its selected route")
    };
    assert_eq!(receipt.session, session);
    assert_eq!(receipt.provider_document_digest, profile.document_digest);
    assert_eq!(receipt.phase, AgentSessionPhaseV1::Ready);
}

fn prompt(
    router: &mut AgentProviderRouter,
    session: protocol::AgentSessionIdV1,
    profile: &AgentProfileSnapshotV1,
    turn: protocol::AgentTurnIdV1,
    prompt: &[u8],
    marker: &[u8],
    seed: u8,
) -> Vec<u8> {
    let mut outcome = router.invoke_agent(&AgentProviderInvocationV1::Prompt {
        request: AgentTurnRequestV1 {
            session,
            turn,
            expected_revision: 1,
            execution: execution(profile, seed),
            prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(prompt).into()),
            prompt: prompt.to_vec(),
        },
        profile: profile.clone(),
        context: Vec::new(),
        now: 20,
    });
    let mut events = Vec::new();
    let mut completed = false;
    for step in 0_u16..=480 {
        let AgentProviderOutcomeV1::Receipt(receipt) = outcome else {
            panic!("live provider prompt became outcome-unknown")
        };
        assert_eq!(receipt.session, session);
        assert_eq!(receipt.provider_document_digest, profile.document_digest);
        events.extend(receipt.events);
        match receipt.phase {
            AgentSessionPhaseV1::Ready => {
                completed = true;
                break;
            }
            AgentSessionPhaseV1::TurnActive => {
                let mut idempotency_key = [seed; 16];
                idempotency_key[1..3].copy_from_slice(&step.to_be_bytes());
                outcome = router.invoke_agent(&AgentProviderInvocationV1::Advance {
                    session,
                    turn,
                    idempotency_key: protocol::IdempotencyKeyV1::new(idempotency_key),
                    now: u64::from(step).saturating_add(21),
                });
            }
            AgentSessionPhaseV1::AwaitingPermission => {
                panic!("no-tool mixed-provider prompt requested permission")
            }
            AgentSessionPhaseV1::Opening
            | AgentSessionPhaseV1::ReattachRequired
            | AgentSessionPhaseV1::OutcomeUnknown
            | AgentSessionPhaseV1::Closed => panic!("invalid live provider prompt phase"),
        }
    }
    assert!(completed, "live provider exceeded bounded advance fuel");
    assert!(!events.iter().any(|record| matches!(
        record.event,
        AgentEventV1::ToolCall { .. }
            | AgentEventV1::Terminal { .. }
            | AgentEventV1::Permission(_)
            | AgentEventV1::FileChange { .. }
            | AgentEventV1::FileRead { .. }
    )));
    let terminal_disposition = events.iter().find_map(|record| match record.event {
        AgentEventV1::TurnFinished { disposition, .. } => Some(disposition),
        _ => None,
    });
    assert_eq!(
        terminal_disposition,
        Some(protocol::ExecutionDispositionV1::Completed),
        "provider did not complete the turn for marker {}",
        String::from_utf8_lossy(marker)
    );
    let output = events
        .iter()
        .filter_map(|record| match &record.event {
            AgentEventV1::AssistantMessage { bytes } => Some(bytes.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert!(!output.is_empty());
    assert!(
        output.windows(marker.len()).any(|window| window == marker),
        "provider output omitted its exact ensemble marker"
    );
    output
}

fn close(router: &mut AgentProviderRouter, session: protocol::AgentSessionIdV1, seed: u8) {
    let AgentProviderOutcomeV1::Receipt(receipt) =
        router.invoke_agent(&AgentProviderInvocationV1::Close {
            session,
            idempotency_key: protocol::IdempotencyKeyV1::new([seed; 16]),
        })
    else {
        panic!("live provider did not close through its retained route")
    };
    assert_eq!(receipt.session, session);
    assert_eq!(receipt.phase, AgentSessionPhaseV1::Closed);
}

/// Opt-in real-process composition gate. This performs initialize/open/close
/// only for both providers and submits no model prompt.
#[test]
#[ignore = "requires explicitly selected authenticated ACP and Claude commands"]
fn genuine_acp_and_claude_sessions_share_one_provider_neutral_router() {
    let acp_program =
        PathBuf::from(std::env::var_os("DAIMON_ROUTER_ACP_PROGRAM").expect("ACP program required"));
    let claude_program = PathBuf::from(
        std::env::var_os("DAIMON_ROUTER_CLAUDE_PROGRAM").expect("Claude program required"),
    );
    assert!(acp_program.is_absolute());
    assert!(claude_program.is_absolute());

    let workspace_path = LiveWorkspace::create();
    let workspace = [92; 16];
    let acp_profile = profile(1, AgentWireProfileV1::AgentClientProtocol);
    let claude_profile = profile(11, AgentWireProfileV1::ClaudeAgentStreamJson);
    let acp = AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_secs(10),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: acp_profile.clone(),
            program: acp_program,
            arguments: arguments("DAIMON_ROUTER_ACP_ARGS"),
            inherited_environment_names: environment("DAIMON_ROUTER_ACP_ENV", "HOME PATH"),
            agent_authentication_method: std::env::var("DAIMON_ROUTER_ACP_AUTH_METHOD")
                .ok()
                .filter(|method| !method.is_empty()),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
            identity: workspace,
            path: workspace_path.0.clone(),
        }],
    )
    .unwrap();
    let claude = ClaudeProvider::try_new(
        ClaudeLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_secs(10),
            ..ClaudeLimitsV1::default()
        },
        vec![ClaudeLaunchProfileV1 {
            snapshot: claude_profile.clone(),
            program: claude_program,
            arguments: arguments("DAIMON_ROUTER_CLAUDE_ARGS"),
            inherited_environment_names: environment(
                "DAIMON_ROUTER_CLAUDE_ENV",
                "HOME PATH SHELL USER LOGNAME TMPDIR LANG LC_ALL TERM CLAUDE_CONFIG_DIR ANTHROPIC_API_KEY",
            ),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![ClaudeWorkspaceV1 {
            identity: workspace,
            path: workspace_path.0.clone(),
        }],
    )
    .unwrap();
    let mut router = AgentProviderRouter::try_new(
        2,
        vec![
            AgentProviderRouteV1 {
                profile_documents: vec![acp_profile.document_digest],
                provider: Box::new(acp),
            },
            AgentProviderRouteV1 {
                profile_documents: vec![claude_profile.document_digest],
                provider: Box::new(claude),
            },
        ],
    )
    .unwrap();
    let acp_session = protocol::AgentSessionIdV1::new([93; 16]);
    let claude_session = protocol::AgentSessionIdV1::new([94; 16]);

    open(&mut router, acp_session, &acp_profile, workspace, 100);
    open(&mut router, claude_session, &claude_profile, workspace, 110);
    close(&mut router, acp_session, 120);
    close(&mut router, claude_session, 121);
}

/// Opt-in live mixed-provider prompt gate. Claude runs first so a stale Claude
/// login cannot consume a Codex turn. Each provider receives one fixed no-tool
/// prompt, must complete without a permission/effect event, and remains bound
/// to its distinct frozen profile evidence through the shared router.
#[test]
#[ignore = "requires explicit two-provider model-spend opt in and authenticated commands"]
fn genuine_acp_and_claude_complete_distinct_no_tool_turns_through_router() {
    if std::env::var("DAIMON_ROUTER_ENABLE_PROMPTS").as_deref() != Ok("1") {
        eprintln!("prompt ensemble skipped; set DAIMON_ROUTER_ENABLE_PROMPTS=1");
        return;
    }
    let acp_program =
        PathBuf::from(std::env::var_os("DAIMON_ROUTER_ACP_PROGRAM").expect("ACP program required"));
    let claude_program = PathBuf::from(
        std::env::var_os("DAIMON_ROUTER_CLAUDE_PROGRAM").expect("Claude program required"),
    );
    assert!(acp_program.is_absolute());
    assert!(claude_program.is_absolute());

    let workspace_path = LiveWorkspace::create();
    let workspace = [92; 16];
    let acp_profile = profile(1, AgentWireProfileV1::AgentClientProtocol);
    let claude_profile = profile(11, AgentWireProfileV1::ClaudeAgentStreamJson);
    let acp = AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            slice_wait: Duration::from_millis(250),
            close_timeout: Duration::from_secs(10),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: acp_profile.clone(),
            program: acp_program,
            arguments: arguments("DAIMON_ROUTER_ACP_ARGS"),
            inherited_environment_names: environment("DAIMON_ROUTER_ACP_ENV", "HOME PATH"),
            agent_authentication_method: std::env::var("DAIMON_ROUTER_ACP_AUTH_METHOD")
                .ok()
                .filter(|method| !method.is_empty()),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
            identity: workspace,
            path: workspace_path.0.clone(),
        }],
    )
    .unwrap();
    let claude = ClaudeProvider::try_new(
        ClaudeLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            slice_wait: Duration::from_millis(250),
            close_timeout: Duration::from_secs(10),
            ..ClaudeLimitsV1::default()
        },
        vec![ClaudeLaunchProfileV1 {
            snapshot: claude_profile.clone(),
            program: claude_program,
            arguments: arguments("DAIMON_ROUTER_CLAUDE_ARGS"),
            inherited_environment_names: environment(
                "DAIMON_ROUTER_CLAUDE_ENV",
                "HOME PATH SHELL USER LOGNAME TMPDIR LANG LC_ALL TERM CLAUDE_CONFIG_DIR ANTHROPIC_API_KEY",
            ),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![ClaudeWorkspaceV1 {
            identity: workspace,
            path: workspace_path.0.clone(),
        }],
    )
    .unwrap();
    let mut router = AgentProviderRouter::try_new(
        2,
        vec![
            AgentProviderRouteV1 {
                profile_documents: vec![acp_profile.document_digest],
                provider: Box::new(acp),
            },
            AgentProviderRouteV1 {
                profile_documents: vec![claude_profile.document_digest],
                provider: Box::new(claude),
            },
        ],
    )
    .unwrap();
    let acp_session = protocol::AgentSessionIdV1::new([93; 16]);
    let claude_session = protocol::AgentSessionIdV1::new([94; 16]);
    open(&mut router, claude_session, &claude_profile, workspace, 110);
    let claude_output = prompt(
        &mut router,
        claude_session,
        &claude_profile,
        protocol::AgentTurnIdV1::new([95; 16]),
        b"Act as the rigor reviewer. Reply with exactly DAIMON_MIXED_CLAUDE_OK. Do not use tools or modify files.",
        b"DAIMON_MIXED_CLAUDE_OK",
        130,
    );
    open(&mut router, acp_session, &acp_profile, workspace, 100);
    let acp_output = prompt(
        &mut router,
        acp_session,
        &acp_profile,
        protocol::AgentTurnIdV1::new([96; 16]),
        b"Act as the historian. Reply with exactly DAIMON_MIXED_ACP_OK. Do not use tools or modify files.",
        b"DAIMON_MIXED_ACP_OK",
        140,
    );
    assert_ne!(claude_output, acp_output);
    assert_ne!(claude_profile.provider, acp_profile.provider);
    assert_ne!(claude_profile.document_digest, acp_profile.document_digest);

    close(&mut router, claude_session, 120);
    close(&mut router, acp_session, 121);
}
