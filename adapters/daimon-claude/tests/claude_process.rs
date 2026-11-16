#![cfg(unix)]

use daimon_claude::{
    ClaudeLaunchProfileV1, ClaudeLimitsV1, ClaudeProvider, ClaudeWorkspaceV1, ProcessIsolationV1,
};
use daimon_host::agent::{AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1};
use daimon_protocol::{self as protocol, agent::*};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, path::PathBuf, thread, time::Duration};

fn profile() -> AgentProfileSnapshotV1 {
    AgentProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([1; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([2; 16]),
        wire: AgentWireProfileV1::ClaudeAgentStreamJson,
        command_digest: protocol::ContentDigestV1::new([3; 32]),
        policy_digest: protocol::ContentDigestV1::new([4; 32]),
        document_digest: protocol::ContentDigestV1::new([5; 32]),
    }
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
            max_tool_calls: 1,
            max_context_bytes: 4_096,
            max_output_bytes: 4_096,
        },
    }
}

fn provider(mode: &str) -> ClaudeProvider {
    provider_with_environment(mode, Vec::new())
}

fn provider_with_environment(
    mode: &str,
    inherited_environment_names: Vec<OsString>,
) -> ClaudeProvider {
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
) -> ClaudeProvider {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = workspace.join("tests/support/fake_claude_agent.sh");
    ClaudeProvider::try_new(
        ClaudeLimitsV1 {
            startup_timeout: Duration::from_secs(2),
            slice_wait: Duration::from_millis(20),
            cancellation_timeout: Duration::from_secs(2),
            close_timeout: Duration::from_secs(2),
            max_events_per_slice: if matches!(mode, "stream" | "cancel_race") {
                1
            } else {
                ClaudeLimitsV1::default().max_events_per_slice
            },
            ..ClaudeLimitsV1::default()
        },
        vec![ClaudeLaunchProfileV1 {
            snapshot: profile(),
            program: fixture,
            arguments: vec![OsString::from(mode), workspace.clone().into_os_string()],
            inherited_environment_names,
            isolation,
        }],
        vec![ClaudeWorkspaceV1 {
            identity: [8; 16],
            path: workspace,
        }],
    )
    .unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn provider_negotiates_through_digest_bound_deny_default_seatbelt() {
    const POLICY: &str = "(version 1) (deny default) (allow process-exec) (allow process-fork) (allow file-read*) (allow sysctl-read)";
    let digest: [u8; 32] = Sha256::digest(POLICY.as_bytes()).into();
    let isolation = ProcessIsolationV1::macos_seatbelt(POLICY.as_bytes().to_vec(), digest).unwrap();
    let mut provider = provider_with_isolation("stream", Vec::new(), isolation);
    open(&mut provider);
}

#[test]
fn launch_diagnostics_redact_arguments_and_environment_names() {
    let launch = ClaudeLaunchProfileV1 {
        snapshot: profile(),
        program: PathBuf::from("/bin/false"),
        arguments: vec![OsString::from("credential-bearing-argument")],
        inherited_environment_names: vec![OsString::from("SECRET_TOKEN_NAME")],
        isolation: ProcessIsolationV1::Direct,
    };
    let debug = format!("{launch:?}");
    assert!(debug.contains("<1 redacted>"));
    assert!(!debug.contains("credential-bearing-argument"));
    assert!(!debug.contains("SECRET_TOKEN_NAME"));
}

#[test]
fn child_environment_is_cleared_except_for_the_exact_allowlist() {
    let mut provider = provider_with_environment("environment", vec![OsString::from("PATH")]);
    open(&mut provider);
}

fn open(provider: &mut ClaudeProvider) {
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
    assert_eq!(receipt.phase, AgentSessionPhaseV1::Ready);
    assert!(receipt.capabilities.permissions);
}

fn prompt(provider: &mut ClaudeProvider) -> AgentProviderOutcomeV1 {
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
fn exact_launch_and_initialize_stream_bounded_progress_then_terminal_evidence() {
    let mut provider = provider("stream");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(first) = prompt(&mut provider) else {
        panic!("first progress slice expected")
    };
    assert_eq!(first.phase, AgentSessionPhaseV1::TurnActive);
    assert!(matches!(
        first.events[0].event,
        AgentEventV1::AssistantMessage { .. }
    ));
    let mut events = first.events;
    let mut phase = first.phase;
    thread::sleep(Duration::from_millis(100));
    for now in 21..24 {
        let AgentProviderOutcomeV1::Receipt(next) =
            provider.invoke_agent(&AgentProviderInvocationV1::Advance {
                session: protocol::AgentSessionIdV1::new([9; 16]),
                turn: protocol::AgentTurnIdV1::new([12; 16]),
                idempotency_key: protocol::IdempotencyKeyV1::new([15; 16]),
                now,
            })
        else {
            panic!("next bounded slice expected")
        };
        phase = next.phase;
        events.extend(next.events);
        if phase == AgentSessionPhaseV1::Ready {
            break;
        }
    }
    assert_eq!(phase, AgentSessionPhaseV1::Ready);
    assert!(
        events
            .iter()
            .any(|record| matches!(record.event, AgentEventV1::Usage { .. }))
    );
    assert!(matches!(
        events.last().unwrap().event,
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
fn permission_selection_returns_exact_correlated_original_input() {
    let mut provider = provider("permission");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(waiting) = prompt(&mut provider) else {
        panic!("permission slice expected")
    };
    assert_eq!(waiting.phase, AgentSessionPhaseV1::AwaitingPermission);
    let AgentEventV1::Permission(permission) = &waiting.events[0].event else {
        panic!("typed permission expected")
    };
    assert_eq!(permission.capability, b"Bash");
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
fn cancellation_requires_correlated_interrupt_ack_and_terminal_result() {
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
fn completion_arriving_before_interrupt_ack_fences_the_cancel_race_as_unknown() {
    let mut provider = provider("cancel_race");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(active) = prompt(&mut provider) else {
        panic!("active slice expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    thread::sleep(Duration::from_millis(70));
    assert_eq!(
        provider.invoke_agent(&AgentProviderInvocationV1::Cancel {
            session: protocol::AgentSessionIdV1::new([9; 16]),
            turn: protocol::AgentTurnIdV1::new([12; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([18; 16]),
        }),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
}

#[test]
fn cancellation_while_permission_waits_denies_then_interrupts_the_same_turn() {
    let mut provider = provider("permission");
    open(&mut provider);
    let AgentProviderOutcomeV1::Receipt(waiting) = prompt(&mut provider) else {
        panic!("permission slice expected")
    };
    assert_eq!(waiting.phase, AgentSessionPhaseV1::AwaitingPermission);
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
fn verified_ambient_context_is_projected_as_verbatim_bounded_content() {
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

#[test]
fn unknown_provider_envelope_is_uncertain_not_retried_or_reinterpreted() {
    let mut provider = provider("malformed");
    open(&mut provider);
    assert_eq!(
        prompt(&mut provider),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
}
