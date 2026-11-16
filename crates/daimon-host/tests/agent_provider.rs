use daimon_host::agent::{
    AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1, AgentProviderReceiptV1,
};
use daimon_protocol::agent::{
    AgentCapabilitiesV1, AgentEventRecordV1, AgentEventV1, AgentOpenRequestV1,
    AgentProfileSnapshotV1, AgentSessionBudgetV1, AgentSessionPhaseV1, AgentWireProfileV1,
};
use daimon_protocol::{
    AgentSessionIdV1, ContentDigestV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionIdV1,
    HarnessProfileIdV1, IdempotencyKeyV1, PrincipalIdV1, ProviderProfileIdV1, TaskAttemptRefV1,
};

struct ScriptedAgent;

impl AgentProvider for ScriptedAgent {
    fn invoke_agent(&mut self, invocation: &AgentProviderInvocationV1) -> AgentProviderOutcomeV1 {
        let AgentProviderInvocationV1::Open {
            request, profile, ..
        } = invocation
        else {
            panic!("open expected")
        };
        AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
            session: request.session,
            provider_document_digest: profile.document_digest,
            phase: AgentSessionPhaseV1::Ready,
            active_turn: None,
            capabilities: AgentCapabilitiesV1 {
                permissions: true,
                terminal: true,
                ..AgentCapabilitiesV1::default()
            },
            recovery: None,
            events: vec![AgentEventRecordV1 {
                cursor: 0,
                event: AgentEventV1::Plan {
                    bytes: b"inspect before editing".to_vec(),
                },
            }],
        })
    }
}

#[test]
fn fake_provider_preserves_typed_events_and_negotiated_capabilities() {
    let profile = AgentProfileSnapshotV1 {
        provider: ProviderProfileIdV1::new([1; 16]),
        harness_profile: HarnessProfileIdV1::new([2; 16]),
        wire: AgentWireProfileV1::AgentClientProtocol,
        command_digest: ContentDigestV1::new([3; 32]),
        policy_digest: ContentDigestV1::new([4; 32]),
        document_digest: ContentDigestV1::new([5; 32]),
    };
    let invocation = AgentProviderInvocationV1::Open {
        request: AgentOpenRequestV1 {
            session: AgentSessionIdV1::new([6; 16]),
            execution: ExecuteRequestV1 {
                execution_id: ExecutionIdV1::new([7; 16]),
                task_attempt: TaskAttemptRefV1 {
                    task_key: [8; 16],
                    task_incarnation: 1,
                    attempt_number: 1,
                },
                principal: PrincipalIdV1::new([9; 16]),
                profile: profile.harness_profile,
                idempotency_key: IdempotencyKeyV1::new([10; 16]),
                context: Vec::new(),
                tools: Vec::new(),
                budget: ExecutionBudgetV1 {
                    max_elapsed_millis: 1_000,
                    max_input_tokens: 100,
                    max_output_tokens: 100,
                    max_tool_calls: 0,
                    max_context_bytes: 1_024,
                    max_output_bytes: 1_024,
                },
            },
            workspace: [8; 16],
            budget: AgentSessionBudgetV1 {
                max_elapsed_millis: 1_000,
                max_turns: 2,
                max_events: 8,
                max_event_bytes: 1_024,
                max_prompt_bytes: 1_024,
                max_permission_requests: 2,
            },
        },
        profile: profile.clone(),
        context: Vec::new(),
    };
    let AgentProviderOutcomeV1::Receipt(receipt) = ScriptedAgent.invoke_agent(&invocation) else {
        panic!("receipt expected")
    };
    assert_eq!(receipt.provider_document_digest, profile.document_digest);
    assert!(receipt.capabilities.permissions);
    assert!(receipt.capabilities.terminal);
    assert!(matches!(receipt.events[0].event, AgentEventV1::Plan { .. }));
}
