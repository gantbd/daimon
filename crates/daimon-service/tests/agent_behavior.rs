use daimon_host::agent::{
    AgentContextAssembler, AgentProfileResolver, AgentProvider, AgentProviderInvocationV1,
    AgentProviderOutcomeV1, AgentProviderReceiptV1, AgentProviderRecoveryV1,
    AgentServiceSnapshotV1, AgentSessionStore,
};
use daimon_host::{
    AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1, AuthorityGrantV1,
    AuthorityRefusalV1, ContextRefusalV1, ExecutionAuthorizer, ProfileRefusalV1, StoreCommitV1,
};
use daimon_protocol as protocol;
use daimon_protocol::agent::{
    AgentCapabilitiesV1, AgentCommandV1, AgentEventRecordV1, AgentEventV1, AgentOpenRequestV1,
    AgentOutcomeV1, AgentPermissionDecisionV1, AgentPermissionOptionKindV1,
    AgentPermissionOptionV1, AgentPermissionRequestV1, AgentProfileSnapshotV1, AgentReplyV1,
    AgentSessionBudgetV1, AgentSessionPhaseV1, AgentTurnRequestV1, AgentTurnStopReasonV1,
    AgentWireProfileV1,
};
use daimon_service::agent::{AgentRecoveryError, AgentService, AgentServiceLimitsV1};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    convert::Infallible,
    rc::Rc,
};

#[derive(Clone, Default)]
struct SharedStore {
    snapshot: Rc<RefCell<Option<AgentServiceSnapshotV1>>>,
    commits: Rc<Cell<usize>>,
    indeterminate_at: Rc<Cell<Option<usize>>>,
}

impl AgentSessionStore for SharedStore {
    type Error = Infallible;

    fn load_agents(&mut self) -> Result<Option<AgentServiceSnapshotV1>, Self::Error> {
        Ok(self.snapshot.borrow().clone())
    }

    fn commit_agents(
        &mut self,
        snapshot: &AgentServiceSnapshotV1,
    ) -> Result<StoreCommitV1, Self::Error> {
        let call = self.commits.get().saturating_add(1);
        self.commits.set(call);
        *self.snapshot.borrow_mut() = Some(snapshot.clone());
        Ok(if self.indeterminate_at.get() == Some(call) {
            StoreCommitV1::Indeterminate
        } else {
            StoreCommitV1::Committed
        })
    }
}

fn execution(execution: u8, idempotency: u8) -> protocol::ExecuteRequestV1 {
    protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([execution; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 1,
            attempt_number: 1,
        },
        principal: protocol::PrincipalIdV1::new([3; 16]),
        profile: protocol::HarnessProfileIdV1::new([4; 16]),
        idempotency_key: protocol::IdempotencyKeyV1::new([idempotency; 16]),
        context: vec![protocol::ContextReferenceIdV1::new([30; 16])],
        tools: Vec::new(),
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

fn open_request() -> AgentOpenRequestV1 {
    AgentOpenRequestV1 {
        session: protocol::AgentSessionIdV1::new([5; 16]),
        execution: execution(6, 7),
        workspace: [8; 16],
        budget: AgentSessionBudgetV1 {
            max_elapsed_millis: 10_000,
            max_turns: 4,
            max_events: 16,
            max_event_bytes: 1_024,
            max_prompt_bytes: 1_024,
            max_permission_requests: 2,
        },
    }
}

fn turn_request() -> AgentTurnRequestV1 {
    let prompt = b"review the boundary".to_vec();
    AgentTurnRequestV1 {
        session: protocol::AgentSessionIdV1::new([5; 16]),
        turn: protocol::AgentTurnIdV1::new([9; 16]),
        expected_revision: 1,
        execution: execution(10, 11),
        prompt_digest: protocol::ContentDigestV1::new(Sha256::digest(&prompt).into()),
        prompt,
    }
}

fn facts() -> AuthenticatedSessionV1 {
    AuthenticatedSessionV1 {
        principal: [3; 16],
        authority_context: [12; 16],
    }
}

struct Allow(Rc<Cell<usize>>);

impl ExecutionAuthorizer for Allow {
    fn authorize(
        &mut self,
        _session: &AuthenticatedSessionV1,
        _request: &protocol::ExecuteRequestV1,
        _now: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
        self.0.set(self.0.get() + 1);
        Ok(AuthorityGrantV1 {
            decision_id: [13; 16],
            expires_at: 100,
            tools: Vec::new(),
        })
    }
}

struct Current(Rc<Cell<usize>>);

impl AttemptValidator for Current {
    fn validate(
        &mut self,
        _session: &AuthenticatedSessionV1,
        _request: &protocol::ExecuteRequestV1,
    ) -> Result<(), AttemptRefusalV1> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}

struct Profiles;

impl AgentProfileResolver for Profiles {
    fn resolve_agent_profile(
        &mut self,
        _service_session: &AuthenticatedSessionV1,
        request: &AgentOpenRequestV1,
    ) -> Result<AgentProfileSnapshotV1, ProfileRefusalV1> {
        Ok(AgentProfileSnapshotV1 {
            provider: protocol::ProviderProfileIdV1::new([14; 16]),
            harness_profile: request.execution.profile,
            wire: AgentWireProfileV1::AgentClientProtocol,
            command_digest: protocol::ContentDigestV1::new([15; 32]),
            policy_digest: protocol::ContentDigestV1::new([16; 32]),
            document_digest: protocol::ContentDigestV1::new([17; 32]),
        })
    }
}

struct Context;

impl AgentContextAssembler for Context {
    fn assemble_agent_context(
        &mut self,
        _service_session: &AuthenticatedSessionV1,
        _request: &AgentOpenRequestV1,
        _profile: &AgentProfileSnapshotV1,
    ) -> Result<Vec<protocol::ContextEvidenceV1>, ContextRefusalV1> {
        Ok(vec![protocol::ContextEvidenceV1 {
            reference: protocol::ContextReferenceIdV1::new([30; 16]),
            kind: protocol::ContextKindV1::VellumDocument,
            bytes: b"exact Vellum revision".to_vec(),
            source_digest: protocol::ContentDigestV1::new([31; 32]),
            grounding: None,
        }])
    }

    fn assemble_agent_turn_context(
        &mut self,
        _service_session: &AuthenticatedSessionV1,
        _request: &AgentTurnRequestV1,
        _profile: &AgentProfileSnapshotV1,
    ) -> Result<Vec<protocol::ContextEvidenceV1>, ContextRefusalV1> {
        self.assemble_agent_context(_service_session, &open_request(), _profile)
    }
}

struct Provider {
    invocations: Rc<RefCell<Vec<AgentProviderInvocationV1>>>,
}

impl AgentProvider for Provider {
    fn invoke_agent(&mut self, invocation: &AgentProviderInvocationV1) -> AgentProviderOutcomeV1 {
        self.invocations.borrow_mut().push(invocation.clone());
        match invocation {
            AgentProviderInvocationV1::Open {
                request, profile, ..
            } => AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                session: request.session,
                provider_document_digest: profile.document_digest,
                phase: AgentSessionPhaseV1::Ready,
                active_turn: None,
                capabilities: AgentCapabilitiesV1 {
                    resume_session: true,
                    permissions: true,
                    terminal: true,
                    ..AgentCapabilitiesV1::default()
                },
                recovery: Some(AgentProviderRecoveryV1 {
                    locator: b"provider-session-5".to_vec(),
                }),
                events: Vec::new(),
            }),
            AgentProviderInvocationV1::Prompt {
                request, profile, ..
            } => {
                let (phase, active_turn, events) = if request.prompt == b"unfinished" {
                    (
                        AgentSessionPhaseV1::Ready,
                        None,
                        vec![AgentEventRecordV1 {
                            cursor: 0,
                            event: AgentEventV1::AssistantMessage {
                                bytes: b"partial".to_vec(),
                            },
                        }],
                    )
                } else if request.prompt == b"keeps running" {
                    (
                        AgentSessionPhaseV1::TurnActive,
                        Some(request.turn),
                        vec![AgentEventRecordV1 {
                            cursor: 0,
                            event: AgentEventV1::Plan {
                                bytes: b"checking boundaries".to_vec(),
                            },
                        }],
                    )
                } else if request.prompt == b"needs permission" {
                    (
                        AgentSessionPhaseV1::AwaitingPermission,
                        Some(request.turn),
                        vec![AgentEventRecordV1 {
                            cursor: 0,
                            event: AgentEventV1::Permission(AgentPermissionRequestV1 {
                                request: protocol::AgentPermissionRequestIdV1::new([30; 16]),
                                turn: request.turn,
                                capability: b"terminal".to_vec(),
                                description: b"run tests".to_vec(),
                                options: vec![AgentPermissionOptionV1 {
                                    id: protocol::AgentPermissionOptionIdV1::new([31; 16]),
                                    kind: AgentPermissionOptionKindV1::AllowOnce,
                                    label: b"allow once".to_vec(),
                                }],
                            }),
                        }],
                    )
                } else {
                    (
                        AgentSessionPhaseV1::Ready,
                        None,
                        vec![
                            AgentEventRecordV1 {
                                cursor: 0,
                                event: AgentEventV1::AssistantMessage {
                                    bytes: b"boundary reviewed".to_vec(),
                                },
                            },
                            AgentEventRecordV1 {
                                cursor: 1,
                                event: AgentEventV1::TurnFinished {
                                    turn: request.turn,
                                    disposition: protocol::ExecutionDispositionV1::Completed,
                                    stop_reason: AgentTurnStopReasonV1::EndTurn,
                                    output_digest: Some(protocol::ContentDigestV1::new([18; 32])),
                                },
                            },
                        ],
                    )
                };
                AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                    session: request.session,
                    provider_document_digest: profile.document_digest,
                    phase,
                    active_turn,
                    capabilities: AgentCapabilitiesV1 {
                        resume_session: true,
                        permissions: true,
                        terminal: true,
                        ..AgentCapabilitiesV1::default()
                    },
                    recovery: Some(AgentProviderRecoveryV1 {
                        locator: b"provider-session-5".to_vec(),
                    }),
                    events,
                })
            }
            AgentProviderInvocationV1::DecidePermission {
                session, decision, ..
            } => {
                assert_eq!(decision.request.into_bytes(), [30; 16]);
                assert_eq!(decision.option.into_bytes(), [31; 16]);
                AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                    session: *session,
                    provider_document_digest: protocol::ContentDigestV1::new([17; 32]),
                    phase: AgentSessionPhaseV1::Ready,
                    active_turn: None,
                    capabilities: AgentCapabilitiesV1 {
                        resume_session: true,
                        permissions: true,
                        terminal: true,
                        ..AgentCapabilitiesV1::default()
                    },
                    recovery: Some(AgentProviderRecoveryV1 {
                        locator: b"provider-session-5".to_vec(),
                    }),
                    events: vec![AgentEventRecordV1 {
                        cursor: 1,
                        event: AgentEventV1::TurnFinished {
                            turn: protocol::AgentTurnIdV1::new([9; 16]),
                            disposition: protocol::ExecutionDispositionV1::Completed,
                            stop_reason: AgentTurnStopReasonV1::EndTurn,
                            output_digest: Some(protocol::ContentDigestV1::new([32; 32])),
                        },
                    }],
                })
            }
            AgentProviderInvocationV1::Advance {
                session,
                turn,
                idempotency_key,
                ..
            } => {
                let (phase, active_turn, event) = if idempotency_key.into_bytes() == [25; 16] {
                    (
                        AgentSessionPhaseV1::TurnActive,
                        Some(*turn),
                        AgentEventV1::AssistantMessage {
                            bytes: b"bounded progress".to_vec(),
                        },
                    )
                } else {
                    (
                        AgentSessionPhaseV1::Ready,
                        None,
                        AgentEventV1::TurnFinished {
                            turn: *turn,
                            disposition: protocol::ExecutionDispositionV1::Completed,
                            stop_reason: AgentTurnStopReasonV1::EndTurn,
                            output_digest: Some(protocol::ContentDigestV1::new([40; 32])),
                        },
                    )
                };
                AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                    session: *session,
                    provider_document_digest: protocol::ContentDigestV1::new([17; 32]),
                    phase,
                    active_turn,
                    capabilities: AgentCapabilitiesV1 {
                        resume_session: true,
                        permissions: true,
                        terminal: true,
                        ..AgentCapabilitiesV1::default()
                    },
                    recovery: Some(AgentProviderRecoveryV1 {
                        locator: b"provider-session-5".to_vec(),
                    }),
                    events: vec![AgentEventRecordV1 {
                        cursor: if active_turn.is_some() { 1 } else { 2 },
                        event,
                    }],
                })
            }
            AgentProviderInvocationV1::Cancel {
                session,
                turn,
                idempotency_key,
            } => {
                let (disposition, stop_reason) = if idempotency_key.into_bytes() == [24; 16] {
                    (
                        protocol::ExecutionDispositionV1::Completed,
                        AgentTurnStopReasonV1::EndTurn,
                    )
                } else {
                    (
                        protocol::ExecutionDispositionV1::Cancelled,
                        AgentTurnStopReasonV1::Cancelled,
                    )
                };
                AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                    session: *session,
                    provider_document_digest: protocol::ContentDigestV1::new([17; 32]),
                    phase: AgentSessionPhaseV1::Ready,
                    active_turn: None,
                    capabilities: AgentCapabilitiesV1 {
                        resume_session: true,
                        permissions: true,
                        terminal: true,
                        ..AgentCapabilitiesV1::default()
                    },
                    recovery: Some(AgentProviderRecoveryV1 {
                        locator: b"provider-session-5".to_vec(),
                    }),
                    events: vec![AgentEventRecordV1 {
                        cursor: 1,
                        event: AgentEventV1::TurnFinished {
                            turn: *turn,
                            disposition,
                            stop_reason,
                            output_digest: None,
                        },
                    }],
                })
            }
            AgentProviderInvocationV1::Close { session, .. } => {
                AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                    session: *session,
                    provider_document_digest: protocol::ContentDigestV1::new([17; 32]),
                    phase: AgentSessionPhaseV1::Closed,
                    active_turn: None,
                    capabilities: AgentCapabilitiesV1::default(),
                    recovery: None,
                    events: Vec::new(),
                })
            }
            AgentProviderInvocationV1::Reattach {
                session,
                recovery,
                profile,
                ..
            } => {
                assert_eq!(recovery.locator, b"provider-session-5");
                AgentProviderOutcomeV1::Receipt(AgentProviderReceiptV1 {
                    session: *session,
                    provider_document_digest: profile.document_digest,
                    phase: AgentSessionPhaseV1::Ready,
                    active_turn: None,
                    capabilities: AgentCapabilitiesV1 {
                        resume_session: true,
                        permissions: true,
                        terminal: true,
                        ..AgentCapabilitiesV1::default()
                    },
                    recovery: Some(recovery.clone()),
                    events: Vec::new(),
                })
            }
        }
    }
}

type Service = AgentService<Allow, Current, Profiles, Context, Provider>;
type Fixture = (
    Service,
    Rc<Cell<usize>>,
    Rc<Cell<usize>>,
    Rc<RefCell<Vec<AgentProviderInvocationV1>>>,
);

fn service() -> Fixture {
    let authorizations = Rc::new(Cell::new(0));
    let attempts = Rc::new(Cell::new(0));
    let invocations = Rc::new(RefCell::new(Vec::new()));
    let service = AgentService::new(
        daimon_harness::Limits::default(),
        AgentServiceLimitsV1 {
            max_service_sessions: 2,
            max_agent_sessions: 4,
            max_events_per_page: 8,
        },
        Allow(Rc::clone(&authorizations)),
        Current(Rc::clone(&attempts)),
        Profiles,
        Context,
        Provider {
            invocations: Rc::clone(&invocations),
        },
    )
    .unwrap();
    (service, authorizations, attempts, invocations)
}

fn durable_service(
    store: SharedStore,
    authorizations: Rc<Cell<usize>>,
    attempts: Rc<Cell<usize>>,
    invocations: Rc<RefCell<Vec<AgentProviderInvocationV1>>>,
) -> AgentService<Allow, Current, Profiles, Context, Provider, SharedStore> {
    AgentService::open(
        daimon_harness::Limits::default(),
        AgentServiceLimitsV1 {
            max_service_sessions: 2,
            max_agent_sessions: 4,
            max_events_per_page: 8,
        },
        Allow(authorizations),
        Current(attempts),
        Profiles,
        Context,
        Provider { invocations },
        store,
    )
    .unwrap()
}

#[test]
fn authorized_open_and_prompt_preserve_typed_events_and_replay_without_redispatch() {
    let (mut service, authorizations, attempts, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    let open = AgentCommandV1::Open {
        request: open_request(),
        now: 10,
    };
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(opened)) = service.execute(handle, open)
    else {
        panic!("opened session expected")
    };
    assert_eq!(opened.revision, 1);
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    assert!(opened.capabilities.permissions);
    let opened_context = opened.last_context.expect("open context receipt");
    assert_eq!(
        opened_context.execution,
        open_request().execution.execution_id
    );
    assert_ne!(opened_context.manifest_digest.into_bytes(), [0; 32]);
    assert_eq!(opened_context.entries.len(), 1);
    assert_eq!(
        opened_context.entries[0].kind,
        protocol::ContextKindV1::VellumDocument
    );
    assert_eq!(
        opened_context.entries[0].source_digest.into_bytes(),
        [31; 32]
    );
    assert_eq!(opened_context.entries[0].content_bytes, 21);

    let prompt = AgentCommandV1::Prompt {
        request: turn_request(),
        now: 11,
    };
    let first = service.execute(handle, prompt.clone());
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(completed)) = &first else {
        panic!("completed turn expected")
    };
    assert_eq!(completed.revision, 2);
    assert_eq!(completed.last_event_cursor, Some(1));
    assert_eq!(
        completed
            .last_context
            .as_ref()
            .expect("turn context receipt")
            .execution,
        turn_request().execution.execution_id
    );

    assert_eq!(service.execute(handle, prompt), first);
    assert_eq!(invocations.borrow().len(), 2);
    assert_eq!(attempts.get(), 2);
    assert_eq!(authorizations.get(), 3);

    let AgentReplyV1::Accepted(AgentOutcomeV1::Events(page)) = service.execute(
        handle,
        AgentCommandV1::Events {
            session: open_request().session,
            after: None,
            limit: 8,
        },
    ) else {
        panic!("event page expected")
    };
    assert_eq!(page.entries.len(), 2);
    assert!(matches!(
        page.entries[0].event,
        AgentEventV1::AssistantMessage { .. }
    ));
    assert!(matches!(
        page.entries[1].event,
        AgentEventV1::TurnFinished { .. }
    ));
}

#[test]
fn completed_turn_exposes_exact_content_free_owner_binding() {
    let (mut service, authorizations, attempts, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    service.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    service.execute(
        handle,
        AgentCommandV1::Prompt {
            request: turn_request(),
            now: 11,
        },
    );

    let reply = service.execute(
        handle,
        AgentCommandV1::Result {
            session: open_request().session,
            turn: turn_request().turn,
        },
    );
    let AgentReplyV1::Accepted(AgentOutcomeV1::Result(binding)) = reply else {
        panic!("owner result binding expected")
    };
    assert_eq!(binding.session, open_request().session);
    assert_eq!(binding.turn, turn_request().turn);
    assert_eq!(binding.execution, turn_request().execution.execution_id);
    assert_eq!(binding.task_attempt, turn_request().execution.task_attempt);
    assert_eq!(binding.principal, turn_request().execution.principal);
    assert_eq!(binding.profile, turn_request().execution.profile);
    assert_eq!(binding.operation, turn_request().execution.idempotency_key);
    assert_eq!(binding.authority_decision, [13; 16]);
    assert_eq!(binding.authority_expires_at, 100);
    assert_eq!(binding.prompt_digest, turn_request().prompt_digest);
    assert_ne!(binding.context_manifest_digest.into_bytes(), [0; 32]);
    assert_eq!(binding.event_start_cursor, 0);
    assert_eq!(binding.terminal_cursor, 1);
    assert_eq!(binding.terminal_revision, 2);
    assert_eq!(
        binding.disposition,
        protocol::ExecutionDispositionV1::Completed
    );
    assert_eq!(binding.stop_reason, AgentTurnStopReasonV1::EndTurn);
    assert_eq!(
        binding.output_digest,
        Some(protocol::ContentDigestV1::new([18; 32]))
    );

    assert_eq!(invocations.borrow().len(), 2);
    assert_eq!(attempts.get(), 2);
    assert_eq!(authorizations.get(), 2);
}

#[test]
fn prompt_turn_identity_cannot_be_reused_under_a_fresh_operation() {
    let (mut service, authorizations, attempts, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    service.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let first = turn_request();
    assert!(matches!(
        service.execute(
            handle,
            AgentCommandV1::Prompt {
                request: first.clone(),
                now: 11,
            },
        ),
        AgentReplyV1::Accepted(AgentOutcomeV1::Session(_))
    ));

    let mut reused = first;
    reused.expected_revision = 2;
    reused.execution.execution_id = protocol::ExecutionIdV1::new([41; 16]);
    reused.execution.idempotency_key = protocol::IdempotencyKeyV1::new([42; 16]);
    assert_eq!(
        service.execute(
            handle,
            AgentCommandV1::Prompt {
                request: reused,
                now: 12,
            },
        ),
        AgentReplyV1::Refused(protocol::agent::AgentRefusalV1::TurnConflict)
    );
    assert_eq!(invocations.borrow().len(), 2);
    assert_eq!(attempts.get(), 2);
    assert_eq!(authorizations.get(), 2);
}

#[test]
fn malformed_prompt_digest_refuses_before_authority_attempt_or_provider() {
    let (mut service, authorizations, attempts, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    service.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let mut request = turn_request();
    request.prompt_digest = protocol::ContentDigestV1::new([99; 32]);
    assert_eq!(
        service.execute(handle, AgentCommandV1::Prompt { request, now: 11 }),
        AgentReplyV1::Refused(protocol::agent::AgentRefusalV1::InvalidInput)
    );
    assert_eq!(invocations.borrow().len(), 1);
    assert_eq!(attempts.get(), 1);
    assert_eq!(authorizations.get(), 1);
}

#[test]
fn ready_without_matching_terminal_event_is_not_completion_evidence() {
    let (mut service, _, _, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    service.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let mut request = turn_request();
    request.prompt = b"unfinished".to_vec();
    request.prompt_digest = protocol::ContentDigestV1::new(Sha256::digest(&request.prompt).into());
    assert_eq!(
        service.execute(handle, AgentCommandV1::Prompt { request, now: 11 }),
        AgentReplyV1::Refused(protocol::agent::AgentRefusalV1::ProviderReceiptMismatch)
    );
    assert_eq!(invocations.borrow().len(), 2);
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)) = service.execute(
        handle,
        AgentCommandV1::Inspect {
            session: open_request().session,
        },
    ) else {
        panic!("session view expected")
    };
    assert_eq!(view.phase, AgentSessionPhaseV1::OutcomeUnknown);
    assert_eq!(view.last_event_cursor, None);
}

#[test]
fn permission_decision_is_exact_separately_authorized_and_replay_safe() {
    let (mut service, authorizations, attempts, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    service.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let mut request = turn_request();
    request.prompt = b"needs permission".to_vec();
    request.prompt_digest = protocol::ContentDigestV1::new(Sha256::digest(&request.prompt).into());
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(waiting)) =
        service.execute(handle, AgentCommandV1::Prompt { request, now: 11 })
    else {
        panic!("permission wait expected")
    };
    assert_eq!(waiting.phase, AgentSessionPhaseV1::AwaitingPermission);
    assert_eq!(waiting.revision, 2);

    let command = AgentCommandV1::DecidePermission {
        session: open_request().session,
        expected_revision: 2,
        execution: execution(20, 21),
        decision: AgentPermissionDecisionV1 {
            request: protocol::AgentPermissionRequestIdV1::new([30; 16]),
            option: protocol::AgentPermissionOptionIdV1::new([31; 16]),
        },
        now: 12,
    };
    let first = service.execute(handle, command.clone());
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(completed)) = &first else {
        panic!("completed permission continuation expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(completed.revision, 3);
    assert_eq!(service.execute(handle, command), first);
    assert_eq!(invocations.borrow().len(), 3);
    assert_eq!(attempts.get(), 3);
    assert_eq!(authorizations.get(), 4);
}

#[test]
fn cancel_and_close_are_exact_owner_scoped_replay_safe_attenuations() {
    let (mut service, authorizations, attempts, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    service.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let mut request = turn_request();
    request.prompt = b"keeps running".to_vec();
    request.prompt_digest = protocol::ContentDigestV1::new(Sha256::digest(&request.prompt).into());
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(active)) = service.execute(
        handle,
        AgentCommandV1::Prompt {
            request: request.clone(),
            now: 11,
        },
    ) else {
        panic!("active turn expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    assert_eq!(active.revision, 2);

    let close = AgentCommandV1::Close {
        session: request.session,
        expected_revision: 2,
        idempotency_key: protocol::IdempotencyKeyV1::new([22; 16]),
        now: 12,
    };
    assert_eq!(
        service.execute(handle, close.clone()),
        AgentReplyV1::Refused(protocol::agent::AgentRefusalV1::Busy)
    );

    let cancel = AgentCommandV1::Cancel {
        session: request.session,
        turn: request.turn,
        expected_revision: 2,
        idempotency_key: protocol::IdempotencyKeyV1::new([23; 16]),
        now: 13,
    };
    let cancelled_reply = service.execute(handle, cancel.clone());
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(cancelled)) = &cancelled_reply else {
        panic!("cancelled turn expected")
    };
    assert_eq!(cancelled.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(cancelled.revision, 3);
    assert_eq!(cancelled.last_event_cursor, Some(1));
    assert_eq!(service.execute(handle, cancel), cancelled_reply);

    let close = AgentCommandV1::Close {
        session: request.session,
        expected_revision: 3,
        idempotency_key: protocol::IdempotencyKeyV1::new([22; 16]),
        now: 14,
    };
    let closed_reply = service.execute(handle, close.clone());
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(closed)) = &closed_reply else {
        panic!("closed session expected")
    };
    assert_eq!(closed.phase, AgentSessionPhaseV1::Closed);
    assert_eq!(closed.revision, 4);
    assert_eq!(service.execute(handle, close), closed_reply);

    assert_eq!(invocations.borrow().len(), 4);
    assert_eq!(attempts.get(), 2);
    assert_eq!(authorizations.get(), 2);
}

#[test]
fn cancel_rejects_normal_completion_as_cancellation_evidence() {
    let (mut service, _, _, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    service.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let mut request = turn_request();
    request.prompt = b"keeps running".to_vec();
    request.prompt_digest = protocol::ContentDigestV1::new(Sha256::digest(&request.prompt).into());
    service.execute(
        handle,
        AgentCommandV1::Prompt {
            request: request.clone(),
            now: 11,
        },
    );

    assert_eq!(
        service.execute(
            handle,
            AgentCommandV1::Cancel {
                session: request.session,
                turn: request.turn,
                expected_revision: 2,
                idempotency_key: protocol::IdempotencyKeyV1::new([24; 16]),
                now: 12,
            },
        ),
        AgentReplyV1::Refused(protocol::agent::AgentRefusalV1::ProviderReceiptMismatch)
    );
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)) = service.execute(
        handle,
        AgentCommandV1::Inspect {
            session: request.session,
        },
    ) else {
        panic!("session view expected")
    };
    assert_eq!(view.phase, AgentSessionPhaseV1::OutcomeUnknown);
    assert_eq!(view.active_turn, Some(request.turn));
    assert_eq!(invocations.borrow().len(), 3);
}

#[test]
fn active_turn_advances_in_bounded_replay_safe_slices() {
    let (mut service, authorizations, attempts, invocations) = service();
    let handle = service.open_service_session(facts()).unwrap();
    service.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let mut request = turn_request();
    request.prompt = b"keeps running".to_vec();
    request.prompt_digest = protocol::ContentDigestV1::new(Sha256::digest(&request.prompt).into());
    service.execute(
        handle,
        AgentCommandV1::Prompt {
            request: request.clone(),
            now: 11,
        },
    );
    assert_eq!(
        service.execute(
            handle,
            AgentCommandV1::Result {
                session: request.session,
                turn: request.turn,
            },
        ),
        AgentReplyV1::Refused(protocol::agent::AgentRefusalV1::Busy)
    );
    let first = AgentCommandV1::Advance {
        session: request.session,
        turn: request.turn,
        expected_revision: 2,
        idempotency_key: protocol::IdempotencyKeyV1::new([25; 16]),
        now: 12,
    };
    let first_reply = service.execute(handle, first.clone());
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(active)) = &first_reply else {
        panic!("active advancement expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    assert_eq!(active.revision, 3);
    assert_eq!(service.execute(handle, first), first_reply);

    let second = AgentCommandV1::Advance {
        session: request.session,
        turn: request.turn,
        expected_revision: 3,
        idempotency_key: protocol::IdempotencyKeyV1::new([26; 16]),
        now: 13,
    };
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(completed)) =
        service.execute(handle, second)
    else {
        panic!("terminal advancement expected")
    };
    assert_eq!(completed.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(completed.revision, 4);
    assert_eq!(completed.last_event_cursor, Some(2));
    assert_eq!(invocations.borrow().len(), 4);
    assert!(matches!(
        &invocations.borrow()[1],
        AgentProviderInvocationV1::Prompt { now: 11, .. }
    ));
    assert!(matches!(
        &invocations.borrow()[2],
        AgentProviderInvocationV1::Advance { now: 12, .. }
    ));
    assert!(matches!(
        &invocations.borrow()[3],
        AgentProviderInvocationV1::Advance { now: 13, .. }
    ));
    assert_eq!(attempts.get(), 2);
    assert_eq!(authorizations.get(), 2);
}

#[test]
fn completed_agent_turn_reopens_and_replays_without_provider_redispatch() {
    let store = SharedStore::default();
    let authorizations = Rc::new(Cell::new(0));
    let attempts = Rc::new(Cell::new(0));
    let invocations = Rc::new(RefCell::new(Vec::new()));
    let mut first = durable_service(
        store.clone(),
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = first.open_service_session(facts()).unwrap();
    let open = AgentCommandV1::Open {
        request: open_request(),
        now: 10,
    };
    first.execute(handle, open.clone());
    let prompt = AgentCommandV1::Prompt {
        request: turn_request(),
        now: 11,
    };
    let completed = first.execute(handle, prompt.clone());
    assert!(matches!(
        completed,
        AgentReplyV1::Accepted(AgentOutcomeV1::Session(_))
    ));
    drop(first);

    let mut reopened = durable_service(
        store,
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = reopened.open_service_session(facts()).unwrap();
    assert!(matches!(
        reopened.execute(handle, open),
        AgentReplyV1::Accepted(AgentOutcomeV1::Session(_))
    ));
    assert_eq!(reopened.execute(handle, prompt), completed);
    assert_eq!(invocations.borrow().len(), 2);
    assert_eq!(attempts.get(), 2);
    assert_eq!(authorizations.get(), 4);
}

#[test]
fn recovery_refuses_mutated_context_manifest_identity() {
    let store = SharedStore::default();
    let mut first = durable_service(
        store.clone(),
        Rc::new(Cell::new(0)),
        Rc::new(Cell::new(0)),
        Rc::new(RefCell::new(Vec::new())),
    );
    let handle = first.open_service_session(facts()).unwrap();
    first.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    first.execute(
        handle,
        AgentCommandV1::Prompt {
            request: turn_request(),
            now: 11,
        },
    );
    drop(first);
    store.snapshot.borrow_mut().as_mut().unwrap().sessions[0]
        .last_context
        .as_mut()
        .unwrap()
        .manifest_digest = protocol::ContentDigestV1::new([99; 32]);

    let reopened = AgentService::open(
        daimon_harness::Limits::default(),
        AgentServiceLimitsV1 {
            max_service_sessions: 2,
            max_agent_sessions: 4,
            max_events_per_page: 8,
        },
        Allow(Rc::new(Cell::new(0))),
        Current(Rc::new(Cell::new(0))),
        Profiles,
        Context,
        Provider {
            invocations: Rc::new(RefCell::new(Vec::new())),
        },
        store,
    );
    assert!(matches!(
        reopened,
        Err(AgentRecoveryError::InvalidSnapshot(
            protocol::agent::AgentRefusalV1::InvalidInput
        ))
    ));
}

#[test]
fn idle_durable_session_requires_explicit_authorized_reattach_and_replays_it_once() {
    let store = SharedStore::default();
    let authorizations = Rc::new(Cell::new(0));
    let attempts = Rc::new(Cell::new(0));
    let invocations = Rc::new(RefCell::new(Vec::new()));
    let mut first = durable_service(
        store.clone(),
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = first.open_service_session(facts()).unwrap();
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(opened)) = first.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    ) else {
        panic!("opened resumable session expected")
    };
    assert_eq!(opened.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(opened.revision, 1);
    drop(first);

    let mut reopened = durable_service(
        store,
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = reopened.open_service_session(facts()).unwrap();
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(detached)) = reopened.execute(
        handle,
        AgentCommandV1::Inspect {
            session: open_request().session,
        },
    ) else {
        panic!("detached session view expected")
    };
    assert_eq!(detached.phase, AgentSessionPhaseV1::ReattachRequired);
    assert_eq!(detached.revision, 1);

    let command = AgentCommandV1::Reattach {
        session: open_request().session,
        expected_revision: 1,
        execution: execution(30, 31),
        now: 20,
    };
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(ready)) =
        reopened.execute(handle, command.clone())
    else {
        panic!("reattached session expected")
    };
    assert_eq!(ready.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(ready.revision, 2);
    assert_eq!(invocations.borrow().len(), 2);
    assert!(matches!(
        &invocations.borrow()[1],
        AgentProviderInvocationV1::Reattach { recovery, .. }
            if recovery.locator == b"provider-session-5"
    ));

    assert_eq!(
        reopened.execute(handle, command.clone()),
        AgentReplyV1::Accepted(AgentOutcomeV1::Session(ready))
    );
    assert_eq!(invocations.borrow().len(), 2);
    assert_eq!(attempts.get(), 2);
    assert_eq!(authorizations.get(), 3);

    let (_, _, _, _, _, store) = reopened.into_parts();
    let mut third = durable_service(
        store,
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = third.open_service_session(facts()).unwrap();
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(still_detached)) =
        third.execute(handle, command)
    else {
        panic!("historical reattach replay must expose the current binding state")
    };
    assert_eq!(still_detached.phase, AgentSessionPhaseV1::ReattachRequired);
    assert_eq!(still_detached.revision, 2);
    assert_eq!(invocations.borrow().len(), 2);

    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(rebound)) = third.execute(
        handle,
        AgentCommandV1::Reattach {
            session: open_request().session,
            expected_revision: 2,
            execution: execution(32, 33),
            now: 21,
        },
    ) else {
        panic!("fresh binding generation expected")
    };
    assert_eq!(rebound.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(rebound.revision, 3);
    assert_eq!(invocations.borrow().len(), 3);
    assert_eq!(attempts.get(), 3);
    assert_eq!(authorizations.get(), 5);
}

#[test]
fn indeterminate_reattach_marker_fences_provider_and_matching_replay() {
    let store = SharedStore::default();
    let authorizations = Rc::new(Cell::new(0));
    let attempts = Rc::new(Cell::new(0));
    let invocations = Rc::new(RefCell::new(Vec::new()));
    let mut first = durable_service(
        store.clone(),
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = first.open_service_session(facts()).unwrap();
    first.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    drop(first);

    store.indeterminate_at.set(Some(3));
    let mut reopened = durable_service(
        store.clone(),
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = reopened.open_service_session(facts()).unwrap();
    let command = AgentCommandV1::Reattach {
        session: open_request().session,
        expected_revision: 1,
        execution: execution(34, 35),
        now: 20,
    };
    let unknown = AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
        session: open_request().session,
        idempotency_key: protocol::IdempotencyKeyV1::new([35; 16]),
    });
    assert_eq!(reopened.execute(handle, command.clone()), unknown);
    assert_eq!(invocations.borrow().len(), 1);
    drop(reopened);

    store.indeterminate_at.set(None);
    let mut third = durable_service(
        store,
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = third.open_service_session(facts()).unwrap();
    assert_eq!(third.execute(handle, command), unknown);
    assert_eq!(invocations.borrow().len(), 1);
}

#[test]
fn active_turn_process_loss_remains_outcome_unknown_and_cannot_reattach() {
    let store = SharedStore::default();
    let authorizations = Rc::new(Cell::new(0));
    let attempts = Rc::new(Cell::new(0));
    let invocations = Rc::new(RefCell::new(Vec::new()));
    let mut first = durable_service(
        store.clone(),
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = first.open_service_session(facts()).unwrap();
    first.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let mut request = turn_request();
    request.prompt = b"keeps running".to_vec();
    request.prompt_digest = protocol::ContentDigestV1::new(Sha256::digest(&request.prompt).into());
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(active)) =
        first.execute(handle, AgentCommandV1::Prompt { request, now: 11 })
    else {
        panic!("active turn expected")
    };
    assert_eq!(active.phase, AgentSessionPhaseV1::TurnActive);
    drop(first);

    let mut reopened = durable_service(
        store,
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = reopened.open_service_session(facts()).unwrap();
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(unknown)) = reopened.execute(
        handle,
        AgentCommandV1::Inspect {
            session: open_request().session,
        },
    ) else {
        panic!("uncertain recovered turn expected")
    };
    assert_eq!(unknown.phase, AgentSessionPhaseV1::OutcomeUnknown);
    assert_eq!(unknown.active_turn, Some(turn_request().turn));
    assert_eq!(
        reopened.execute(
            handle,
            AgentCommandV1::Reattach {
                session: open_request().session,
                expected_revision: unknown.revision,
                execution: execution(36, 37),
                now: 20,
            },
        ),
        AgentReplyV1::Refused(protocol::agent::AgentRefusalV1::Busy)
    );
    assert_eq!(invocations.borrow().len(), 2);
}

#[test]
fn indeterminate_agent_marker_commit_fences_provider_and_survives_reopen() {
    let store = SharedStore::default();
    store.indeterminate_at.set(Some(1));
    let authorizations = Rc::new(Cell::new(0));
    let attempts = Rc::new(Cell::new(0));
    let invocations = Rc::new(RefCell::new(Vec::new()));
    let mut first = durable_service(
        store.clone(),
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = first.open_service_session(facts()).unwrap();
    let open = AgentCommandV1::Open {
        request: open_request(),
        now: 10,
    };
    assert_eq!(
        first.execute(handle, open.clone()),
        AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session: open_request().session,
            idempotency_key: open_request().execution.idempotency_key,
        })
    );
    assert!(invocations.borrow().is_empty());
    drop(first);

    store.indeterminate_at.set(None);
    let mut reopened = durable_service(
        store,
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = reopened.open_service_session(facts()).unwrap();
    assert_eq!(
        reopened.execute(handle, open),
        AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session: open_request().session,
            idempotency_key: open_request().execution.idempotency_key,
        })
    );
    assert!(invocations.borrow().is_empty());
    assert_eq!(attempts.get(), 1);
    assert_eq!(authorizations.get(), 2);
}

#[test]
fn indeterminate_agent_result_commit_reopens_exact_result_without_redispatch() {
    let store = SharedStore::default();
    store.indeterminate_at.set(Some(4));
    let authorizations = Rc::new(Cell::new(0));
    let attempts = Rc::new(Cell::new(0));
    let invocations = Rc::new(RefCell::new(Vec::new()));
    let mut first = durable_service(
        store.clone(),
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = first.open_service_session(facts()).unwrap();
    first.execute(
        handle,
        AgentCommandV1::Open {
            request: open_request(),
            now: 10,
        },
    );
    let prompt = AgentCommandV1::Prompt {
        request: turn_request(),
        now: 11,
    };
    assert_eq!(
        first.execute(handle, prompt.clone()),
        AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session: open_request().session,
            idempotency_key: turn_request().execution.idempotency_key,
        })
    );
    assert_eq!(invocations.borrow().len(), 2);
    assert_eq!(
        first.execute(
            handle,
            AgentCommandV1::Result {
                session: open_request().session,
                turn: turn_request().turn,
            },
        ),
        AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session: open_request().session,
            idempotency_key: turn_request().execution.idempotency_key,
        })
    );
    drop(first);

    store.indeterminate_at.set(None);
    let mut reopened = durable_service(
        store,
        Rc::clone(&authorizations),
        Rc::clone(&attempts),
        Rc::clone(&invocations),
    );
    let handle = reopened.open_service_session(facts()).unwrap();
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)) = reopened.execute(handle, prompt)
    else {
        panic!("retained completed turn expected")
    };
    assert_eq!(view.revision, 2);
    assert_eq!(view.phase, AgentSessionPhaseV1::Ready);
    assert_eq!(invocations.borrow().len(), 2);
    assert_eq!(attempts.get(), 2);
    assert_eq!(authorizations.get(), 3);
}
