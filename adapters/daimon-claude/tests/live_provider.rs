#![cfg(unix)]

use daimon_claude::{
    ClaudeLaunchProfileV1, ClaudeLimitsV1, ClaudeProvider, ClaudeWorkspaceV1, ProcessIsolationV1,
};
use daimon_host::agent::{AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1};
use daimon_protocol::{self as protocol, agent::*};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, fs, path::PathBuf, time::Duration};

struct LiveWorkspace(PathBuf);

impl LiveWorkspace {
    fn create(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{label}-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for LiveWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Opt-in, no-prompt compatibility gate for a genuine Claude Code command.
///
/// This performs only the Agent SDK control-channel initialize handshake and
/// local close. It deliberately submits no user message and incurs no model turn.
#[test]
#[ignore = "requires an explicitly selected installed and authenticated Claude Code command"]
fn genuine_claude_initializes_and_closes_without_prompt() {
    let program =
        PathBuf::from(std::env::var_os("DAIMON_CLAUDE_PROGRAM").expect("program required"));
    assert!(program.is_absolute());
    let arguments = std::env::var("DAIMON_CLAUDE_ARGS")
        .unwrap_or_default()
        .split_whitespace()
        .map(OsString::from)
        .collect();
    let workspace = LiveWorkspace::create("daimon-claude-live");
    let snapshot = AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([1; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([2; 16]),
        wire: AgentWireProfileV1::ClaudeAgentStreamJson,
        command_digest: protocol::ContentDigestV1::new([3; 32]),
        policy_digest: protocol::ContentDigestV1::new([4; 32]),
        document_digest: protocol::ContentDigestV1::new([5; 32]),
    };
    let mut provider = ClaudeProvider::try_new(
        ClaudeLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_secs(10),
            ..ClaudeLimitsV1::default()
        },
        vec![ClaudeLaunchProfileV1 {
            snapshot: snapshot.clone(),
            program,
            arguments,
            inherited_environment_names: [
                "HOME",
                "PATH",
                "SHELL",
                "USER",
                "LOGNAME",
                "TMPDIR",
                "LANG",
                "LC_ALL",
                "TERM",
                "CLAUDE_CONFIG_DIR",
                "ANTHROPIC_API_KEY",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![ClaudeWorkspaceV1 {
            identity: [8; 16],
            path: workspace.0.clone(),
        }],
    )
    .unwrap();
    let session = protocol::AgentSessionIdV1::new([9; 16]);
    let outcome = provider.invoke_agent(&AgentProviderInvocationV1::Open {
        request: AgentOpenRequestV1 {
            session,
            execution: execution(snapshot.harness_profile),
            workspace: [8; 16],
            budget: AgentSessionBudgetV1 {
                max_elapsed_millis: 30_000,
                max_turns: 1,
                max_events: 8,
                max_event_bytes: 4_096,
                max_prompt_bytes: 4_096,
                max_permission_requests: 1,
            },
        },
        profile: snapshot,
        context: Vec::new(),
    });
    let AgentProviderOutcomeV1::Receipt(opened) = outcome else {
        panic!("genuine Claude provider did not initialize")
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session,
            idempotency_key: protocol::IdempotencyKeyV1::new([10; 16]),
        })
    else {
        panic!("genuine Claude provider did not close")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

/// Opt-in bounded no-tool prompt through Claude's genuine bidirectional
/// stream-JSON transport. This gate never answers a permission request.
#[test]
#[ignore = "requires explicit model-spend opt in and authenticated Claude Code"]
fn genuine_claude_completes_one_no_tool_prompt() {
    if std::env::var("DAIMON_CLAUDE_ENABLE_PROMPT").as_deref() != Ok("1") {
        eprintln!("prompt gate skipped; set DAIMON_CLAUDE_ENABLE_PROMPT=1");
        return;
    }
    let program =
        PathBuf::from(std::env::var_os("DAIMON_CLAUDE_PROGRAM").expect("program required"));
    assert!(program.is_absolute());
    let arguments = std::env::var("DAIMON_CLAUDE_ARGS")
        .unwrap_or_default()
        .split_whitespace()
        .map(OsString::from)
        .collect();
    let workspace = LiveWorkspace::create("daimon-claude-live-prompt");
    let snapshot = AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([21; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([22; 16]),
        wire: AgentWireProfileV1::ClaudeAgentStreamJson,
        command_digest: protocol::ContentDigestV1::new([23; 32]),
        policy_digest: protocol::ContentDigestV1::new([24; 32]),
        document_digest: protocol::ContentDigestV1::new([25; 32]),
    };
    let mut provider = ClaudeProvider::try_new(
        ClaudeLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            slice_wait: Duration::from_millis(250),
            close_timeout: Duration::from_secs(10),
            ..ClaudeLimitsV1::default()
        },
        vec![ClaudeLaunchProfileV1 {
            snapshot: snapshot.clone(),
            program,
            arguments,
            inherited_environment_names: [
                "HOME",
                "PATH",
                "SHELL",
                "USER",
                "LOGNAME",
                "TMPDIR",
                "LANG",
                "LC_ALL",
                "TERM",
                "CLAUDE_CONFIG_DIR",
                "ANTHROPIC_API_KEY",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![ClaudeWorkspaceV1 {
            identity: [28; 16],
            path: workspace.0.clone(),
        }],
    )
    .unwrap();
    let session = protocol::AgentSessionIdV1::new([29; 16]);
    let AgentProviderOutcomeV1::Receipt(opened) =
        provider.invoke_agent(&AgentProviderInvocationV1::Open {
            request: AgentOpenRequestV1 {
                session,
                execution: execution(snapshot.harness_profile),
                workspace: [28; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 120_000,
                    max_turns: 1,
                    max_events: 128,
                    max_event_bytes: 64 * 1024,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 1,
                },
            },
            profile: snapshot.clone(),
            context: Vec::new(),
        })
    else {
        panic!("genuine Claude provider did not initialize")
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    let prompt = b"Reply with exactly MOIRA_CLAUDE_OK. Do not use tools or modify files.".to_vec();
    let turn = protocol::AgentTurnIdV1::new([30; 16]);
    let mut outcome = provider.invoke_agent(&AgentProviderInvocationV1::Prompt {
        request: AgentTurnRequestV1 {
            session,
            turn,
            expected_revision: 1,
            execution: execution(snapshot.harness_profile),
            prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&prompt).into()),
            prompt,
        },
        profile: snapshot,
        context: Vec::new(),
        now: 20,
    });
    let mut events = Vec::new();
    let mut completed = false;
    // One advance waits at most 250 ms. Keep the independent polling fuel
    // aligned with the session's 120-second elapsed-time budget instead of
    // cutting the provider off at roughly half of that declared bound.
    for step in 0_u16..=480 {
        let AgentProviderOutcomeV1::Receipt(receipt) = outcome else {
            panic!("Claude prompt outcome became unknown")
        };
        events.extend(receipt.events);
        match receipt.phase {
            AgentSessionPhaseV1::Ready => {
                completed = true;
                break;
            }
            AgentSessionPhaseV1::TurnActive => {
                let mut idempotency_key = [0_u8; 16];
                idempotency_key[0] = 31;
                idempotency_key[1..3].copy_from_slice(&step.to_be_bytes());
                outcome = provider.invoke_agent(&AgentProviderInvocationV1::Advance {
                    session,
                    turn,
                    idempotency_key: protocol::IdempotencyKeyV1::new(idempotency_key),
                    now: u64::from(step).saturating_add(21),
                });
            }
            AgentSessionPhaseV1::AwaitingPermission => {
                panic!("no-tool Claude prompt requested permission; no approval was sent")
            }
            AgentSessionPhaseV1::Opening
            | AgentSessionPhaseV1::ReattachRequired
            | AgentSessionPhaseV1::OutcomeUnknown
            | AgentSessionPhaseV1::Closed => panic!("invalid live Claude prompt phase"),
        }
    }
    assert!(completed, "Claude prompt exceeded bounded advance fuel");
    assert!(events.iter().any(|record| matches!(
        record.event,
        AgentEventV1::AssistantMessage { ref bytes } if !bytes.is_empty()
    )));
    let terminal_disposition = events.iter().find_map(|record| match record.event {
        AgentEventV1::TurnFinished { disposition, .. } => Some(disposition),
        _ => None,
    });
    assert_eq!(
        terminal_disposition,
        Some(protocol::ExecutionDispositionV1::Completed),
        "Claude did not return a completed terminal disposition"
    );
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session,
            idempotency_key: protocol::IdempotencyKeyV1::new([250; 16]),
        })
    else {
        panic!("genuine Claude provider did not close")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

fn execution(profile: protocol::HarnessProfileIdV1) -> protocol::ExecuteRequestV1 {
    protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([11; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [12; 16],
            task_incarnation: 1,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([13; 16]),
        profile,
        idempotency_key: protocol::IdempotencyKeyV1::new([14; 16]),
        context: Vec::new(),
        tools: Vec::new(),
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: 30_000,
            max_input_tokens: 1_024,
            max_output_tokens: 1_024,
            max_tool_calls: 0,
            max_context_bytes: 4_096,
            max_output_bytes: 4_096,
        },
    }
}
