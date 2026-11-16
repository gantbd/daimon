#![cfg(unix)]

use daimon_acp::{
    AcpLaunchProfileV1, AcpLimitsV1, AcpProvider, AcpWorkspaceV1, ProcessIsolationV1,
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

/// Opt-in, no-prompt compatibility gate for a genuine ACP provider command.
///
/// `DAIMON_ACP_PROGRAM=/absolute/path`, optional whitespace-separated
/// `DAIMON_ACP_ARGS`, an exact `DAIMON_ACP_ENV` name allowlist, and optional
/// `DAIMON_ACP_AUTH_METHOD` agent-handled method select the provider. This
/// negotiates, creates, and closes one session but deliberately sends no model
/// prompt and incurs no model spend.
#[test]
#[ignore = "requires an explicitly selected installed and authenticated ACP provider"]
fn genuine_provider_negotiates_creates_and_closes_without_prompt() {
    let program = PathBuf::from(std::env::var_os("DAIMON_ACP_PROGRAM").expect("program required"));
    assert!(program.is_absolute());
    let arguments = std::env::var("DAIMON_ACP_ARGS")
        .unwrap_or_default()
        .split_whitespace()
        .map(OsString::from)
        .collect();
    let workspace = LiveWorkspace::create("daimon-acp-live");
    let snapshot = AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([1; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([2; 16]),
        wire: AgentWireProfileV1::AgentClientProtocol,
        command_digest: protocol::ContentDigestV1::new([3; 32]),
        policy_digest: protocol::ContentDigestV1::new([4; 32]),
        document_digest: protocol::ContentDigestV1::new([5; 32]),
    };
    let mut provider = AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_secs(10),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: snapshot.clone(),
            program,
            arguments,
            inherited_environment_names: inherited_environment_names(),
            agent_authentication_method: authentication_method(),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
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
    let opened = match outcome {
        AgentProviderOutcomeV1::Receipt(opened) => opened,
        other => panic!("genuine provider did not open: {other:?}"),
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session,
            idempotency_key: protocol::IdempotencyKeyV1::new([10; 16]),
        })
    else {
        panic!("genuine provider did not close")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

/// Opt-in restart gate for a genuine resume-capable ACP provider.
///
/// One bounded no-tool turn gives the provider durable history, after which this
/// deliberately drops the first adapter process while its session is idle,
/// starts a fresh adapter process with the same frozen profile, and requires an
/// explicit ACP `session/resume`. Reattachment sends no implicit prompt or
/// `session/load` and therefore must return no replayed conversation events.
#[test]
#[ignore = "requires model-spend opt in and an installed resume-capable ACP provider"]
fn genuine_provider_reattaches_idle_session_without_history_replay() {
    if std::env::var("DAIMON_ACP_ENABLE_REATTACH_PROMPT").as_deref() != Ok("1") {
        eprintln!(
            "reattach gate skipped; set DAIMON_ACP_ENABLE_REATTACH_PROMPT=1 to authorize one seed turn"
        );
        return;
    }
    let program = PathBuf::from(std::env::var_os("DAIMON_ACP_PROGRAM").expect("program required"));
    assert!(program.is_absolute());
    let arguments = std::env::var("DAIMON_ACP_ARGS")
        .unwrap_or_default()
        .split_whitespace()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let workspace = LiveWorkspace::create("daimon-acp-live-reattach");
    let snapshot = AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([61; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([62; 16]),
        wire: AgentWireProfileV1::AgentClientProtocol,
        command_digest: protocol::ContentDigestV1::new([63; 32]),
        policy_digest: protocol::ContentDigestV1::new([64; 32]),
        document_digest: protocol::ContentDigestV1::new([65; 32]),
    };
    let request = AgentOpenRequestV1 {
        session: protocol::AgentSessionIdV1::new([66; 16]),
        execution: execution(snapshot.harness_profile),
        workspace: [67; 16],
        budget: AgentSessionBudgetV1 {
            max_elapsed_millis: 120_000,
            max_turns: 1,
            max_events: 8,
            max_event_bytes: 4_096,
            max_prompt_bytes: 4_096,
            max_permission_requests: 1,
        },
    };
    let provider = || {
        AcpProvider::try_new(
            AcpLimitsV1 {
                startup_timeout: Duration::from_secs(30),
                slice_wait: Duration::from_millis(250),
                close_timeout: Duration::from_secs(10),
                ..AcpLimitsV1::default()
            },
            vec![AcpLaunchProfileV1 {
                snapshot: snapshot.clone(),
                program: program.clone(),
                arguments: arguments.clone(),
                inherited_environment_names: inherited_environment_names(),
                agent_authentication_method: authentication_method(),
                isolation: ProcessIsolationV1::Direct,
            }],
            vec![AcpWorkspaceV1 {
                identity: [67; 16],
                path: workspace.0.clone(),
            }],
        )
        .unwrap()
    };

    let mut first = provider();
    let AgentProviderOutcomeV1::Receipt(opened) =
        first.invoke_agent(&AgentProviderInvocationV1::Open {
            request: request.clone(),
            profile: snapshot.clone(),
            context: Vec::new(),
        })
    else {
        panic!("genuine provider did not open a resumable session")
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    assert!(opened.capabilities.resume_session);
    assert!(opened.events.is_empty());
    let recovery = opened
        .recovery
        .expect("genuine provider must return a bounded recovery locator");

    let prompt =
        b"Reply with exactly DAIMON_REATTACH_SEED_OK. Do not use tools or modify files.".to_vec();
    let turn = protocol::AgentTurnIdV1::new([71; 16]);
    let mut outcome = first.invoke_agent(&AgentProviderInvocationV1::Prompt {
        request: AgentTurnRequestV1 {
            session: request.session,
            turn,
            expected_revision: 1,
            execution: execution(snapshot.harness_profile),
            prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&prompt).into()),
            prompt,
        },
        profile: snapshot.clone(),
        context: Vec::new(),
        now: 10,
    });
    let mut completed = false;
    let mut saw_terminal = false;
    for step in 0_u16..=480 {
        let AgentProviderOutcomeV1::Receipt(receipt) = outcome else {
            panic!("provider seed turn became outcome-unknown")
        };
        saw_terminal |= receipt.events.iter().any(|record| {
            matches!(
                record.event,
                AgentEventV1::TurnFinished {
                    disposition: protocol::ExecutionDispositionV1::Completed,
                    ..
                }
            )
        });
        match receipt.phase {
            AgentSessionPhaseV1::Ready => {
                completed = true;
                break;
            }
            AgentSessionPhaseV1::TurnActive => {
                outcome = first.invoke_agent(&AgentProviderInvocationV1::Advance {
                    session: request.session,
                    turn,
                    idempotency_key: advance_key(72, step),
                    now: u64::from(step).saturating_add(11),
                });
            }
            AgentSessionPhaseV1::AwaitingPermission => {
                panic!("no-tool reattach seed requested permission")
            }
            AgentSessionPhaseV1::Opening
            | AgentSessionPhaseV1::ReattachRequired
            | AgentSessionPhaseV1::OutcomeUnknown
            | AgentSessionPhaseV1::Closed => panic!("invalid reattach seed phase"),
        }
    }
    assert!(
        completed,
        "provider seed turn exceeded bounded advance fuel"
    );
    assert!(saw_terminal, "provider seed turn lacked completed evidence");
    drop(first);

    let mut reattach_execution = execution(snapshot.harness_profile);
    reattach_execution.execution_id = protocol::ExecutionIdV1::new([68; 16]);
    reattach_execution.idempotency_key = protocol::IdempotencyKeyV1::new([69; 16]);
    let mut second = provider();
    let outcome = second.invoke_agent(&AgentProviderInvocationV1::Reattach {
        session: request.session,
        execution: reattach_execution,
        original_open: Box::new(request),
        profile: snapshot,
        context: Vec::new(),
        recovery: recovery.clone(),
        now: 20,
    });
    let AgentProviderOutcomeV1::Receipt(reattached) = outcome else {
        panic!("genuine provider did not reattach: {outcome:?}")
    };
    assert_eq!(reattached.phase, AgentSessionPhaseV1::Ready);
    assert!(
        reattached.events.is_empty(),
        "resume must not replay history"
    );
    assert_eq!(reattached.recovery, Some(recovery));

    let AgentProviderOutcomeV1::Receipt(closed) =
        second.invoke_agent(&AgentProviderInvocationV1::Close {
            session: reattached.session,
            idempotency_key: protocol::IdempotencyKeyV1::new([70; 16]),
        })
    else {
        panic!("genuine reattached provider did not close")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

/// Opt-in bounded prompt qualification for a genuine provider. This test never
/// approves a permission request: a provider that asks for one is reported as
/// not qualified for the no-tool prompt profile.
#[test]
#[ignore = "requires explicit model-spend opt in and an authenticated ACP provider"]
fn genuine_provider_completes_one_no_tool_prompt() {
    if std::env::var("DAIMON_ACP_ENABLE_PROMPT").as_deref() != Ok("1") {
        eprintln!("prompt gate skipped; set DAIMON_ACP_ENABLE_PROMPT=1");
        return;
    }
    let program = PathBuf::from(std::env::var_os("DAIMON_ACP_PROGRAM").expect("program required"));
    assert!(program.is_absolute());
    let arguments = std::env::var("DAIMON_ACP_ARGS")
        .unwrap_or_default()
        .split_whitespace()
        .map(OsString::from)
        .collect();
    let workspace = LiveWorkspace::create("daimon-acp-live-prompt");
    let snapshot = AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([21; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([22; 16]),
        wire: AgentWireProfileV1::AgentClientProtocol,
        command_digest: protocol::ContentDigestV1::new([23; 32]),
        policy_digest: protocol::ContentDigestV1::new([24; 32]),
        document_digest: protocol::ContentDigestV1::new([25; 32]),
    };
    let mut provider = AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            slice_wait: Duration::from_millis(250),
            close_timeout: Duration::from_secs(10),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: snapshot.clone(),
            program,
            arguments,
            inherited_environment_names: inherited_environment_names(),
            agent_authentication_method: authentication_method(),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
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
                    // The session can represent one request so that the adapter
                    // reports it faithfully; this qualification never approves it.
                    max_permission_requests: 1,
                },
            },
            profile: snapshot.clone(),
            context: Vec::new(),
        })
    else {
        panic!("genuine provider did not open")
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    let prompt = b"Reply with exactly MOIRA_ACP_OK. Do not use tools or modify files.".to_vec();
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
    // aligned with the session's 120-second elapsed-time budget.
    for step in 0_u16..=480 {
        let AgentProviderOutcomeV1::Receipt(receipt) = outcome else {
            panic!("provider prompt outcome became unknown")
        };
        events.extend(receipt.events);
        match receipt.phase {
            AgentSessionPhaseV1::Ready => {
                completed = true;
                break;
            }
            AgentSessionPhaseV1::TurnActive => {
                outcome = provider.invoke_agent(&AgentProviderInvocationV1::Advance {
                    session,
                    turn,
                    idempotency_key: advance_key(31, step),
                    now: u64::from(step).saturating_add(21),
                });
            }
            AgentSessionPhaseV1::AwaitingPermission => {
                panic!("no-tool prompt requested permission; no approval was sent")
            }
            AgentSessionPhaseV1::Opening
            | AgentSessionPhaseV1::ReattachRequired
            | AgentSessionPhaseV1::OutcomeUnknown
            | AgentSessionPhaseV1::Closed => panic!("invalid live prompt phase"),
        }
    }
    assert!(completed, "provider prompt exceeded bounded advance fuel");
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
        "provider did not return a completed terminal disposition"
    );
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session,
            idempotency_key: protocol::IdempotencyKeyV1::new([250; 16]),
        })
    else {
        panic!("genuine provider did not close")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

/// Opt-in genuine permission correlation gate. The requested network command is
/// rejected once; this test never selects an allow option.
#[test]
#[ignore = "requires explicit model-spend opt in and an authenticated ACP provider"]
fn genuine_provider_permission_can_be_rejected_without_granting_capability() {
    if std::env::var("DAIMON_ACP_ENABLE_PERMISSION_PROMPT").as_deref() != Ok("1") {
        eprintln!("permission gate skipped; set DAIMON_ACP_ENABLE_PERMISSION_PROMPT=1");
        return;
    }
    let program = PathBuf::from(std::env::var_os("DAIMON_ACP_PROGRAM").expect("program required"));
    assert!(program.is_absolute());
    let arguments = std::env::var("DAIMON_ACP_ARGS")
        .unwrap_or_default()
        .split_whitespace()
        .map(OsString::from)
        .collect();
    let workspace = LiveWorkspace::create("daimon-acp-live-permission");
    let snapshot = AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([41; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([42; 16]),
        wire: AgentWireProfileV1::AgentClientProtocol,
        command_digest: protocol::ContentDigestV1::new([43; 32]),
        policy_digest: protocol::ContentDigestV1::new([44; 32]),
        document_digest: protocol::ContentDigestV1::new([45; 32]),
    };
    let mut provider = AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(30),
            slice_wait: Duration::from_millis(250),
            close_timeout: Duration::from_secs(10),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: snapshot.clone(),
            program,
            arguments,
            inherited_environment_names: inherited_environment_names(),
            agent_authentication_method: authentication_method(),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
            identity: [48; 16],
            path: workspace.0.clone(),
        }],
    )
    .unwrap();
    let session = protocol::AgentSessionIdV1::new([49; 16]);
    let AgentProviderOutcomeV1::Receipt(opened) =
        provider.invoke_agent(&AgentProviderInvocationV1::Open {
            request: AgentOpenRequestV1 {
                session,
                execution: execution(snapshot.harness_profile),
                workspace: [48; 16],
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
        panic!("genuine provider did not open")
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);

    let sentinel = PathBuf::from(format!(
        "/private/tmp/daimon-acp-permission-probe-nonexistent-{}",
        std::process::id()
    ));
    assert!(!sentinel.exists());
    let prompt = format!(
        "Use the shell to run exactly `rm -rf {}` once. Do not use another tool or answer without attempting that command.",
        sentinel.display()
    )
    .into_bytes();
    let turn = protocol::AgentTurnIdV1::new([50; 16]);
    let mut outcome = provider.invoke_agent(&AgentProviderInvocationV1::Prompt {
        request: AgentTurnRequestV1 {
            session,
            turn,
            expected_revision: 1,
            execution: execution(snapshot.harness_profile),
            prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&prompt).into()),
            prompt,
        },
        profile: snapshot.clone(),
        context: Vec::new(),
        now: 20,
    });
    let mut permission = None;
    for step in 0_u16..=480 {
        let AgentProviderOutcomeV1::Receipt(receipt) = outcome else {
            panic!("provider permission request became outcome-unknown")
        };
        for record in receipt.events {
            if let AgentEventV1::Permission(request) = record.event {
                assert!(permission.replace(request).is_none());
            }
        }
        match receipt.phase {
            AgentSessionPhaseV1::AwaitingPermission => break,
            AgentSessionPhaseV1::TurnActive => {
                outcome = provider.invoke_agent(&AgentProviderInvocationV1::Advance {
                    session,
                    turn,
                    idempotency_key: advance_key(51, step),
                    now: u64::from(step).saturating_add(21),
                });
            }
            AgentSessionPhaseV1::Ready => {
                panic!("provider completed without the required permission challenge")
            }
            AgentSessionPhaseV1::Opening
            | AgentSessionPhaseV1::ReattachRequired
            | AgentSessionPhaseV1::OutcomeUnknown
            | AgentSessionPhaseV1::Closed => panic!("invalid live permission phase"),
        }
    }
    let permission = permission.expect("typed permission challenge required");
    assert_eq!(permission.turn, turn);
    let reject = permission
        .options
        .iter()
        .find(|option| option.kind == AgentPermissionOptionKindV1::RejectOnce)
        .expect("reject-once option required");
    let mut outcome = provider.invoke_agent(&AgentProviderInvocationV1::DecidePermission {
        session,
        execution: execution(snapshot.harness_profile),
        decision: AgentPermissionDecisionV1 {
            request: permission.request,
            option: reject.id,
        },
        now: 600,
    });
    let mut terminal = false;
    let mut completed = false;
    for step in 0_u16..=480 {
        let AgentProviderOutcomeV1::Receipt(receipt) = outcome else {
            panic!("provider outcome after rejection became unknown")
        };
        terminal |= receipt.events.iter().any(|record| {
            matches!(
                record.event,
                AgentEventV1::TurnFinished {
                    turn: finished_turn,
                    ..
                } if finished_turn == turn
            )
        });
        match receipt.phase {
            AgentSessionPhaseV1::Ready => {
                completed = true;
                break;
            }
            AgentSessionPhaseV1::TurnActive => {
                outcome = provider.invoke_agent(&AgentProviderInvocationV1::Advance {
                    session,
                    turn,
                    idempotency_key: advance_key(52, step),
                    now: u64::from(step).saturating_add(601),
                });
            }
            AgentSessionPhaseV1::AwaitingPermission => {
                panic!("provider requested a second permission after reject-once")
            }
            AgentSessionPhaseV1::Opening
            | AgentSessionPhaseV1::ReattachRequired
            | AgentSessionPhaseV1::OutcomeUnknown
            | AgentSessionPhaseV1::Closed => panic!("invalid post-rejection phase"),
        }
    }
    assert!(
        completed,
        "provider did not terminate after permission rejection"
    );
    assert!(terminal, "matching terminal event required after rejection");
    assert!(!sentinel.exists());
    let AgentProviderOutcomeV1::Receipt(closed) =
        provider.invoke_agent(&AgentProviderInvocationV1::Close {
            session,
            idempotency_key: protocol::IdempotencyKeyV1::new([53; 16]),
        })
    else {
        panic!("genuine provider did not close")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
}

fn advance_key(prefix: u8, step: u16) -> protocol::IdempotencyKeyV1 {
    let mut bytes = [0_u8; 16];
    bytes[0] = prefix;
    bytes[1..3].copy_from_slice(&step.to_be_bytes());
    protocol::IdempotencyKeyV1::new(bytes)
}

fn inherited_environment_names() -> Vec<OsString> {
    std::env::var("DAIMON_ACP_ENV")
        .unwrap_or_else(|_| "HOME PATH".to_owned())
        .split_whitespace()
        .map(OsString::from)
        .collect()
}

fn authentication_method() -> Option<String> {
    std::env::var("DAIMON_ACP_AUTH_METHOD")
        .ok()
        .filter(|method| !method.is_empty())
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
            max_input_tokens: 512,
            max_output_tokens: 512,
            max_tool_calls: 0,
            max_context_bytes: 4_096,
            max_output_bytes: 4_096,
        },
    }
}
