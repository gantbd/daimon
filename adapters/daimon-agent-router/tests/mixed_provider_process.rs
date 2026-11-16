#![cfg(unix)]

use daimon_acp::{
    AcpLaunchProfileV1, AcpLimitsV1, AcpProvider, AcpWorkspaceV1, ProcessIsolationV1,
};
use daimon_agent_router::{AgentProviderRouteV1, AgentProviderRouter};
use daimon_claude::{ClaudeLaunchProfileV1, ClaudeLimitsV1, ClaudeProvider, ClaudeWorkspaceV1};
use daimon_host::agent::{AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1};
use daimon_protocol::{self as protocol, agent::*};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, path::PathBuf, thread, time::Duration};

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

fn execution(profile: &AgentProfileSnapshotV1, seed: u8) -> protocol::ExecuteRequestV1 {
    protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([seed; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [70; 16],
            task_incarnation: 1,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([71; 16]),
        profile: profile.harness_profile,
        idempotency_key: protocol::IdempotencyKeyV1::new([seed + 1; 16]),
        context: Vec::new(),
        tools: Vec::new(),
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: 5_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 0,
            max_context_bytes: 4_096,
            max_output_bytes: 4_096,
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
                    max_elapsed_millis: 10_000,
                    max_turns: 2,
                    max_events: 32,
                    max_event_bytes: 4_096,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 2,
                },
            },
            profile: profile.clone(),
            context: Vec::new(),
        })
    else {
        panic!("open receipt expected")
    };
    assert_eq!(receipt.session, session);
    assert_eq!(receipt.provider_document_digest, profile.document_digest);
    assert_eq!(receipt.phase, AgentSessionPhaseV1::Ready);
}

fn complete_prompt(
    router: &mut AgentProviderRouter,
    session: protocol::AgentSessionIdV1,
    turn: protocol::AgentTurnIdV1,
    profile: &AgentProfileSnapshotV1,
    seed: u8,
) -> Vec<String> {
    let prompt = b"produce one bounded observation".to_vec();
    let mut outcome = router.invoke_agent(&AgentProviderInvocationV1::Prompt {
        request: AgentTurnRequestV1 {
            session,
            turn,
            expected_revision: 1,
            execution: execution(profile, seed),
            prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&prompt).into()),
            prompt,
        },
        profile: profile.clone(),
        context: Vec::new(),
        now: 20,
    });
    let mut messages = Vec::new();
    for advance in 0_u8..20 {
        let AgentProviderOutcomeV1::Receipt(receipt) = outcome else {
            panic!("provider outcome became ambiguous")
        };
        assert_eq!(receipt.session, session);
        assert_eq!(receipt.provider_document_digest, profile.document_digest);
        let mut finished = false;
        for event in receipt.events {
            match event.event {
                AgentEventV1::AssistantMessage { bytes } => {
                    messages.push(String::from_utf8(bytes).unwrap());
                }
                AgentEventV1::TurnFinished { .. } => finished = true,
                _ => {}
            }
        }
        if receipt.phase == AgentSessionPhaseV1::Ready && finished {
            return messages;
        }
        assert_eq!(receipt.phase, AgentSessionPhaseV1::TurnActive);
        thread::sleep(Duration::from_millis(20));
        outcome = router.invoke_agent(&AgentProviderInvocationV1::Advance {
            session,
            turn,
            idempotency_key: protocol::IdempotencyKeyV1::new([seed.wrapping_add(advance + 2); 16]),
            now: u64::from(advance).saturating_add(21),
        });
    }
    panic!("bounded provider turn did not finish")
}

fn close(router: &mut AgentProviderRouter, session: protocol::AgentSessionIdV1, seed: u8) {
    let AgentProviderOutcomeV1::Receipt(receipt) =
        router.invoke_agent(&AgentProviderInvocationV1::Close {
            session,
            idempotency_key: protocol::IdempotencyKeyV1::new([seed; 16]),
        })
    else {
        panic!("close receipt expected")
    };
    assert_eq!(receipt.phase, AgentSessionPhaseV1::Closed);
}

#[test]
fn acp_and_claude_sessions_share_one_provider_neutral_router() {
    let router_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let adapters = router_manifest.parent().unwrap();
    let acp_workspace = adapters.join("daimon-acp").canonicalize().unwrap();
    let claude_workspace = adapters.join("daimon-claude").canonicalize().unwrap();
    let acp_fixture = acp_workspace
        .join("tests/support/fake_acp_agent.sh")
        .canonicalize()
        .unwrap();
    let claude_fixture = claude_workspace
        .join("tests/support/fake_claude_agent.sh")
        .canonicalize()
        .unwrap();
    let acp_profile = profile(1, AgentWireProfileV1::AgentClientProtocol);
    let claude_profile = profile(11, AgentWireProfileV1::ClaudeAgentStreamJson);
    let workspace = [72; 16];

    let acp = AcpProvider::try_new(
        AcpLimitsV1 {
            startup_timeout: Duration::from_secs(2),
            slice_wait: Duration::from_millis(20),
            cancellation_timeout: Duration::from_secs(2),
            close_timeout: Duration::from_secs(2),
            ..AcpLimitsV1::default()
        },
        vec![AcpLaunchProfileV1 {
            snapshot: acp_profile.clone(),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![acp_fixture.into_os_string(), OsString::from("stream")],
            inherited_environment_names: Vec::new(),
            agent_authentication_method: None,
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![AcpWorkspaceV1 {
            identity: workspace,
            path: acp_workspace,
        }],
    )
    .unwrap();
    let claude = ClaudeProvider::try_new(
        ClaudeLimitsV1 {
            startup_timeout: Duration::from_secs(2),
            slice_wait: Duration::from_millis(20),
            cancellation_timeout: Duration::from_secs(2),
            close_timeout: Duration::from_secs(2),
            ..ClaudeLimitsV1::default()
        },
        vec![ClaudeLaunchProfileV1 {
            snapshot: claude_profile.clone(),
            program: claude_fixture,
            arguments: vec![
                OsString::from("stream"),
                claude_workspace.clone().into_os_string(),
            ],
            inherited_environment_names: Vec::new(),
            isolation: ProcessIsolationV1::Direct,
        }],
        vec![ClaudeWorkspaceV1 {
            identity: workspace,
            path: claude_workspace,
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
    let acp_session = protocol::AgentSessionIdV1::new([73; 16]);
    let claude_session = protocol::AgentSessionIdV1::new([74; 16]);

    open(&mut router, acp_session, &acp_profile, workspace, 80);
    open(&mut router, claude_session, &claude_profile, workspace, 90);
    let acp_messages = complete_prompt(
        &mut router,
        acp_session,
        protocol::AgentTurnIdV1::new([75; 16]),
        &acp_profile,
        100,
    );
    let claude_messages = complete_prompt(
        &mut router,
        claude_session,
        protocol::AgentTurnIdV1::new([76; 16]),
        &claude_profile,
        110,
    );

    assert_eq!(acp_messages, ["first slice", "second slice"]);
    assert_eq!(claude_messages, ["first slice", "second slice"]);
    close(&mut router, acp_session, 120);
    close(&mut router, claude_session, 121);
}
