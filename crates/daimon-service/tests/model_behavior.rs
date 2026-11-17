use daimon_host::{
    AssembledModelInputV1, AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1,
    AuthorityGrantV1, AuthorityRefusalV1, ContextAssembler, ContextRefusalV1, ExecutionAuthorizer,
    ModelExecutionStore, ModelProvider, ModelProviderOutcomeV1, ModelServiceSnapshotV1,
    ProfileRefusalV1, ProviderProfileResolver, StoreCommitV1,
};
use daimon_protocol as protocol;
use daimon_service::{
    ServiceLimitsV1,
    model::{ModelService, VolatileModelStore},
};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    convert::Infallible,
    rc::Rc,
};

fn request() -> protocol::ExecuteRequestV1 {
    protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([1; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 3,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([4; 16]),
        profile: protocol::HarnessProfileIdV1::new([5; 16]),
        idempotency_key: protocol::IdempotencyKeyV1::new([6; 16]),
        context: vec![protocol::ContextReferenceIdV1::new([7; 16])],
        tools: vec![],
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 1,
            max_context_bytes: 1_024,
            max_output_bytes: 1_024,
        },
    }
}

fn session() -> AuthenticatedSessionV1 {
    AuthenticatedSessionV1 {
        principal: [4; 16],
        authority_context: [8; 16],
    }
}

struct Allow;

impl ExecutionAuthorizer for Allow {
    fn authorize(
        &mut self,
        _session: &AuthenticatedSessionV1,
        _request: &protocol::ExecuteRequestV1,
        _now: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
        Ok(AuthorityGrantV1 {
            decision_id: [9; 16],
            expires_at: 100,
            tools: vec![],
        })
    }
}

struct CurrentAttempt;

impl AttemptValidator for CurrentAttempt {
    fn validate(
        &mut self,
        _session: &AuthenticatedSessionV1,
        _request: &protocol::ExecuteRequestV1,
    ) -> Result<(), AttemptRefusalV1> {
        Ok(())
    }
}

struct LocalProfile;

impl ProviderProfileResolver for LocalProfile {
    fn resolve_profile(
        &mut self,
        _session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
    ) -> Result<protocol::ProviderProfileSnapshotV1, ProfileRefusalV1> {
        Ok(protocol::ProviderProfileSnapshotV1 {
            provider: protocol::ProviderProfileIdV1::new([10; 16]),
            harness_profile: request.profile,
            wire: protocol::ProviderWireProfileV1::OpenAiChatCompletions,
            model: b"local-model".to_vec(),
            structured_tools: false,
            document_digest: protocol::ContentDigestV1::new([11; 32]),
        })
    }
}

struct Context;

impl ContextAssembler for Context {
    fn assemble(
        &mut self,
        _session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
        _profile: &protocol::ProviderProfileSnapshotV1,
    ) -> Result<AssembledModelInputV1, ContextRefusalV1> {
        Ok(AssembledModelInputV1 {
            context: vec![protocol::ContextEvidenceV1 {
                reference: request.context[0],
                kind: protocol::ContextKindV1::AgoraMessage,
                bytes: b"question".to_vec(),
                source_digest: protocol::ContentDigestV1::new([12; 32]),
                grounding: None,
            }],
            messages: vec![protocol::ModelMessageV1 {
                role: protocol::MessageRoleV1::User,
                content: b"question".to_vec(),
            }],
            estimated_input_tokens: 2,
        })
    }
}

struct Provider {
    calls: Rc<Cell<usize>>,
}

impl ModelProvider for Provider {
    fn execute_model(
        &mut self,
        invocation: &protocol::ModelInvocationV1,
    ) -> ModelProviderOutcomeV1 {
        self.calls.set(self.calls.get() + 1);
        ModelProviderOutcomeV1::Receipt(protocol::ModelProviderReceiptV1 {
            execution_id: invocation.execution_id,
            provider_document_digest: invocation.provider.document_digest,
            evidence_digest: protocol::ContentDigestV1::new([13; 32]),
            disposition: protocol::ExecutionDispositionV1::Completed,
            input_tokens: 2,
            output_tokens: 3,
            output: b"answer".to_vec(),
            proposals: vec![
                protocol::OutputProposalV1::AgoraMessage(protocol::AgoraMessageProposalV1 {
                    room: [14; 16],
                    reply_to: [15; 16],
                    body: b"answer".to_vec(),
                }),
                protocol::OutputProposalV1::VellumEdit(protocol::VellumEditProposalV1 {
                    workspace: [16; 16],
                    document: [17; 16],
                    expected_revision: 4,
                    replacement: b"reviewed edit".to_vec(),
                }),
            ],
        })
    }
}

fn limits() -> (daimon_harness::Limits, ServiceLimitsV1) {
    (
        daimon_harness::Limits::default(),
        ServiceLimitsV1 {
            max_sessions: 4,
            max_executions: 8,
        },
    )
}

struct ToolAllow;

impl ExecutionAuthorizer for ToolAllow {
    fn authorize(
        &mut self,
        _session: &AuthenticatedSessionV1,
        _request: &protocol::ExecuteRequestV1,
        _now: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
        Ok(AuthorityGrantV1 {
            decision_id: [9; 16],
            expires_at: 100,
            tools: vec![protocol::ToolCapabilityIdV1::new([20; 16])],
        })
    }
}

struct ToolProfile;

impl ProviderProfileResolver for ToolProfile {
    fn resolve_profile(
        &mut self,
        _session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
    ) -> Result<protocol::ProviderProfileSnapshotV1, ProfileRefusalV1> {
        Ok(protocol::ProviderProfileSnapshotV1 {
            provider: protocol::ProviderProfileIdV1::new([10; 16]),
            harness_profile: request.profile,
            wire: protocol::ProviderWireProfileV1::OpenAiChatCompletions,
            model: b"local-model".to_vec(),
            structured_tools: true,
            document_digest: protocol::ContentDigestV1::new([11; 32]),
        })
    }
}

struct ToolProvider {
    invocations: Rc<RefCell<Vec<protocol::ModelInvocationV1>>>,
}

impl ModelProvider for ToolProvider {
    fn execute_model(
        &mut self,
        invocation: &protocol::ModelInvocationV1,
    ) -> ModelProviderOutcomeV1 {
        self.invocations.borrow_mut().push(invocation.clone());
        let proposals = if invocation.continuation.is_none() {
            vec![protocol::OutputProposalV1::ToolCall(
                protocol::ToolCallProposalV1 {
                    request: [21; 16],
                    capability: protocol::ToolCapabilityIdV1::new([20; 16]),
                    provider_correlation: b"call-21".to_vec(),
                    arguments: br#"{"path":"README.md"}"#.to_vec(),
                },
            )]
        } else {
            Vec::new()
        };
        ModelProviderOutcomeV1::Receipt(protocol::ModelProviderReceiptV1 {
            execution_id: invocation.execution_id,
            provider_document_digest: invocation.provider.document_digest,
            evidence_digest: protocol::ContentDigestV1::new([13; 32]),
            disposition: protocol::ExecutionDispositionV1::Completed,
            input_tokens: 2,
            output_tokens: 3,
            output: if invocation.continuation.is_none() {
                Vec::new()
            } else {
                b"answer after tool".to_vec()
            },
            proposals,
        })
    }
}

#[test]
fn completed_native_calls_resume_once_with_exact_retained_provider_correlation() {
    let invocations = Rc::new(RefCell::new(Vec::new()));
    let (engine_limits, service_limits) = limits();
    let mut service = ModelService::new(
        engine_limits,
        service_limits,
        ToolAllow,
        CurrentAttempt,
        ToolProfile,
        Context,
        ToolProvider {
            invocations: Rc::clone(&invocations),
        },
    )
    .unwrap();
    let handle = service.open_session(session()).unwrap();
    let mut source = request();
    source.tools = vec![protocol::ToolCapabilityIdV1::new([20; 16])];
    let first = service.execute(
        handle,
        protocol::ModelCommandV1::Execute {
            request: source.clone(),
            now: 10,
        },
    );
    assert!(matches!(
        first,
        protocol::ModelReplyV1::Accepted(protocol::ModelOutcomeV1::Executed(_))
    ));
    let (_, _, _, _, provider, store) = service.into_parts();
    let mut service = ModelService::open(
        engine_limits,
        service_limits,
        ToolAllow,
        CurrentAttempt,
        ToolProfile,
        Context,
        provider,
        store,
    )
    .unwrap();
    let handle = service.open_session(session()).unwrap();

    let output = b"tool output".to_vec();
    let output_digest = protocol::ContentDigestV1::new(Sha256::digest(&output).into());
    let mut resumed = source;
    resumed.execution_id = protocol::ExecutionIdV1::new([30; 16]);
    resumed.idempotency_key = protocol::IdempotencyKeyV1::new([31; 16]);
    resumed.tools.clear();
    let command = protocol::ModelCommandV1::Resume {
        request: resumed,
        source_execution: protocol::ExecutionIdV1::new([1; 16]),
        results: vec![protocol::ResumeToolResultV1 {
            request: [21; 16],
            evidence_digest: protocol::ContentDigestV1::new([22; 32]),
            output_digest,
            output: output.clone(),
        }],
        now: 11,
    };
    let reply = service.execute(handle, command.clone());
    let protocol::ModelReplyV1::Accepted(protocol::ModelOutcomeV1::Executed(result)) = &reply
    else {
        panic!("expected resumed result, got {reply:?}")
    };
    assert_eq!(result.output, b"answer after tool");
    let captured = invocations.borrow();
    assert_eq!(captured.len(), 2);
    let continuation = captured[1].continuation.as_ref().unwrap();
    assert!(captured[1].tools.is_empty());
    assert_eq!(continuation.source_execution.into_bytes(), [1; 16]);
    assert_eq!(continuation.results[0].provider_correlation, b"call-21");
    assert_eq!(continuation.results[0].output, output);
    drop(captured);

    let (_, _, _, _, provider, store) = service.into_parts();
    let mut reopened = ModelService::open(
        engine_limits,
        service_limits,
        ToolAllow,
        CurrentAttempt,
        ToolProfile,
        Context,
        provider,
        store,
    )
    .unwrap();
    let handle = reopened.open_session(session()).unwrap();
    assert_eq!(reopened.execute(handle, command), reply);
    assert_eq!(invocations.borrow().len(), 2);
}

#[test]
fn typed_result_reopens_and_replays_without_profile_context_or_provider_redispatch() {
    let calls = Rc::new(Cell::new(0));
    let (engine_limits, service_limits) = limits();
    let mut service = ModelService::new(
        engine_limits,
        service_limits,
        Allow,
        CurrentAttempt,
        LocalProfile,
        Context,
        Provider {
            calls: Rc::clone(&calls),
        },
    )
    .unwrap();
    let handle = service.open_session(session()).unwrap();
    let command = protocol::ModelCommandV1::Execute {
        request: request(),
        now: 10,
    };
    let first = service.execute(handle, command.clone());
    let protocol::ModelReplyV1::Accepted(protocol::ModelOutcomeV1::Executed(result)) = &first
    else {
        panic!("expected typed model result: {first:?}");
    };
    assert_eq!(result.proposals.len(), 2);
    assert_eq!(calls.get(), 1);

    let (_, _, _, _, provider, store) = service.into_parts();
    let mut reopened = ModelService::open(
        engine_limits,
        service_limits,
        Allow,
        CurrentAttempt,
        LocalProfile,
        Context,
        provider,
        store,
    )
    .unwrap();
    let reopened_handle = reopened.open_session(session()).unwrap();
    assert_eq!(reopened.execute(reopened_handle, command), first);
    assert_eq!(calls.get(), 1);
}

#[derive(Clone)]
struct IndeterminateStore {
    snapshot: Rc<RefCell<Option<ModelServiceSnapshotV1>>>,
}

impl ModelExecutionStore for IndeterminateStore {
    type Error = Infallible;

    fn load_model(&mut self) -> Result<Option<ModelServiceSnapshotV1>, Self::Error> {
        Ok(self.snapshot.borrow().clone())
    }

    fn commit_model(
        &mut self,
        snapshot: &ModelServiceSnapshotV1,
    ) -> Result<StoreCommitV1, Self::Error> {
        *self.snapshot.borrow_mut() = Some(snapshot.clone());
        Ok(StoreCommitV1::Indeterminate)
    }
}

#[test]
fn indeterminate_marker_commit_fences_before_local_model_admission() {
    let calls = Rc::new(Cell::new(0));
    let shared = Rc::new(RefCell::new(None));
    let (engine_limits, service_limits) = limits();
    let mut service = ModelService::open(
        engine_limits,
        service_limits,
        Allow,
        CurrentAttempt,
        LocalProfile,
        Context,
        Provider {
            calls: Rc::clone(&calls),
        },
        IndeterminateStore {
            snapshot: Rc::clone(&shared),
        },
    )
    .unwrap();
    let handle = service.open_session(session()).unwrap();
    assert_eq!(
        service.execute(
            handle,
            protocol::ModelCommandV1::Execute {
                request: request(),
                now: 10,
            }
        ),
        protocol::ModelReplyV1::Accepted(protocol::ModelOutcomeV1::OutcomeUnknown {
            execution_id: protocol::ExecutionIdV1::new([1; 16]),
        })
    );
    assert_eq!(calls.get(), 0);
    assert!(shared.borrow().is_some());
}

#[test]
fn volatile_model_store_type_remains_public_for_embedded_composition() {
    let _store = VolatileModelStore::default();
}
