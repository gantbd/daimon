use daimon_agent_router::{
    AgentProviderRouteV1, AgentProviderRouter, AgentRouterConfigurationErrorV1,
    StaticAgentProfileRouter,
};
use daimon_host::AuthenticatedSessionV1;
use daimon_host::agent::{
    AgentProfileResolver, AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1,
};
use daimon_protocol::{self as protocol, agent::*};
use std::{cell::RefCell, rc::Rc};

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
            task_key: [31; 16],
            task_incarnation: 1,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([32; 16]),
        profile: profile.harness_profile,
        idempotency_key: protocol::IdempotencyKeyV1::new([seed + 1; 16]),
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

fn open(
    session: protocol::AgentSessionIdV1,
    profile: AgentProfileSnapshotV1,
) -> AgentProviderInvocationV1 {
    AgentProviderInvocationV1::Open {
        request: AgentOpenRequestV1 {
            session,
            execution: execution(&profile, 40),
            workspace: [41; 16],
            budget: AgentSessionBudgetV1 {
                max_elapsed_millis: 1_000,
                max_turns: 1,
                max_events: 8,
                max_event_bytes: 1_024,
                max_prompt_bytes: 1_024,
                max_permission_requests: 0,
            },
        },
        profile,
        context: Vec::new(),
    }
}

struct ObservedProvider {
    calls: Rc<RefCell<usize>>,
}

impl AgentProvider for ObservedProvider {
    fn invoke_agent(&mut self, _invocation: &AgentProviderInvocationV1) -> AgentProviderOutcomeV1 {
        *self.calls.borrow_mut() += 1;
        AgentProviderOutcomeV1::OutcomeUnknown
    }
}

#[test]
fn ambiguous_open_is_fenced_to_one_backend_before_dispatch() {
    let acp = profile(1, AgentWireProfileV1::AgentClientProtocol);
    let claude = profile(11, AgentWireProfileV1::ClaudeAgentStreamJson);
    let acp_calls = Rc::new(RefCell::new(0));
    let claude_calls = Rc::new(RefCell::new(0));
    let mut router = AgentProviderRouter::try_new(
        2,
        vec![
            AgentProviderRouteV1 {
                profile_documents: vec![acp.document_digest],
                provider: Box::new(ObservedProvider {
                    calls: acp_calls.clone(),
                }),
            },
            AgentProviderRouteV1 {
                profile_documents: vec![claude.document_digest],
                provider: Box::new(ObservedProvider {
                    calls: claude_calls.clone(),
                }),
            },
        ],
    )
    .unwrap();
    let session = protocol::AgentSessionIdV1::new([50; 16]);

    assert_eq!(
        router.invoke_agent(&open(session, acp)),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
    assert_eq!(
        router.invoke_agent(&open(session, claude)),
        AgentProviderOutcomeV1::OutcomeUnknown
    );
    assert_eq!(*acp_calls.borrow(), 1);
    assert_eq!(*claude_calls.borrow(), 0);
}

#[test]
fn profile_registry_is_bounded_and_rejects_aliases() {
    let acp = profile(1, AgentWireProfileV1::AgentClientProtocol);
    let mut alias = profile(11, AgentWireProfileV1::ClaudeAgentStreamJson);
    alias.harness_profile = acp.harness_profile;
    assert!(matches!(
        StaticAgentProfileRouter::try_new(2, vec![acp.clone(), alias]),
        Err(AgentRouterConfigurationErrorV1::DuplicateProfile)
    ));
    assert!(matches!(
        StaticAgentProfileRouter::try_new(
            1,
            vec![
                acp.clone(),
                profile(21, AgentWireProfileV1::AgentClientProtocol)
            ]
        ),
        Err(AgentRouterConfigurationErrorV1::InvalidLimits)
    ));

    let mut resolver = StaticAgentProfileRouter::try_new(1, vec![acp.clone()]).unwrap();
    let AgentProviderInvocationV1::Open { request, .. } =
        open(protocol::AgentSessionIdV1::new([51; 16]), acp.clone())
    else {
        unreachable!()
    };
    assert_eq!(
        resolver
            .resolve_agent_profile(
                &AuthenticatedSessionV1 {
                    principal: [32; 16],
                    authority_context: [52; 16],
                },
                &request,
            )
            .unwrap(),
        acp
    );
}
