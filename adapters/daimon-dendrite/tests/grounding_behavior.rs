use daimon_dendrite::{
    ContextBindingV1, DendriteClient, GroundingContextAssembler, SurfaceEntryV1, SurfaceQueryV1,
    SurfaceResponseV1,
};
use daimon_host::{AuthenticatedSessionV1, ContextAssembler, ContextRefusalV1};
use daimon_protocol as protocol;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap, convert::Infallible, rc::Rc};

fn digest(bytes: &[u8]) -> protocol::ContentDigestV1 {
    protocol::ContentDigestV1::new(Sha256::digest(bytes).into())
}

const AUTHORITY: &[u8] = b"(grounding example (surface activated (entry question \"why?\")))";
const CANONICAL: &[u8] =
    br#"{"version":1,"depth":"activated","entries":[{"kind":"question","text":"why?"}]}"#;

#[derive(Clone)]
struct Client {
    calls: Rc<RefCell<Vec<String>>>,
    surface_digest: protocol::ContentDigestV1,
}

impl DendriteClient for Client {
    type Error = Infallible;

    fn query_surface(&mut self, query: &SurfaceQueryV1) -> Result<SurfaceResponseV1, Self::Error> {
        self.calls.borrow_mut().push(format!(
            "surface:{}:{}:{:?}",
            query.load_id, query.target, query.depth
        ));
        Ok(SurfaceResponseV1 {
            version: 1,
            target: query.target.clone(),
            depth: query.depth,
            entries: vec![SurfaceEntryV1 {
                id: None,
                kind: "question".into(),
                text: "why?".into(),
            }],
            grounding_digest: digest(AUTHORITY),
            surface_digest: self.surface_digest,
        })
    }

    fn read_ref(&mut self, load_id: &str, target: &str) -> Result<Vec<u8>, Self::Error> {
        self.calls
            .borrow_mut()
            .push(format!("read:{load_id}:{target}"));
        Ok(AUTHORITY.to_vec())
    }
}

fn request(reference: protocol::ContextReferenceIdV1) -> protocol::ExecuteRequestV1 {
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
        context: vec![reference],
        tools: vec![],
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

fn profile() -> protocol::ProviderProfileSnapshotV1 {
    protocol::ProviderProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new([7; 16]),
        harness_profile: protocol::HarnessProfileIdV1::new([5; 16]),
        wire: protocol::ProviderWireProfileV1::OpenAiChatCompletions,
        model: b"model".to_vec(),
        structured_tools: false,
        document_digest: protocol::ContentDigestV1::new([8; 32]),
    }
}

fn assembler(
    surface_digest: protocol::ContentDigestV1,
) -> (GroundingContextAssembler<Client>, Rc<RefCell<Vec<String>>>) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let reference = protocol::ContextReferenceIdV1::new([9; 16]);
    let bindings = BTreeMap::from([(
        reference,
        ContextBindingV1::Dendrite {
            query: SurfaceQueryV1 {
                load_id: "engineering".into(),
                target: "rune:rust".into(),
                depth: protocol::GroundingDepthV1::Activated,
            },
            expected_grounding_digest: digest(AUTHORITY),
            expected_surface_digest: digest(CANONICAL),
        },
    )]);
    let assembler = GroundingContextAssembler::try_new(
        Client {
            calls: Rc::clone(&calls),
            surface_digest,
        },
        bindings,
        vec![protocol::ModelMessageV1 {
            role: protocol::MessageRoleV1::User,
            content: b"question".to_vec(),
        }],
        2,
        1_024,
    )
    .unwrap();
    (assembler, calls)
}

#[test]
fn exact_authority_and_canonical_surface_digests_produce_grounding_evidence() {
    let (mut assembler, calls) = assembler(digest(CANONICAL));
    let reference = protocol::ContextReferenceIdV1::new([9; 16]);
    let input = assembler
        .assemble(
            &AuthenticatedSessionV1 {
                principal: [4; 16],
                authority_context: [10; 16],
            },
            &request(reference),
            &profile(),
        )
        .unwrap();
    assert_eq!(input.context[0].bytes, CANONICAL);
    assert_eq!(
        input.context[0].grounding,
        Some(protocol::GroundingEvidenceV1 {
            depth: protocol::GroundingDepthV1::Activated,
            grounding_digest: digest(AUTHORITY),
            surface_digest: digest(CANONICAL),
        })
    );
    assert_eq!(
        calls.borrow().as_slice(),
        [
            "surface:engineering:rune:rust:Activated",
            "read:engineering:rune:rust"
        ]
    );
}

#[test]
fn surface_drift_refuses_instead_of_adopting_new_grounding() {
    let (mut assembler, _) = assembler(protocol::ContentDigestV1::new([99; 32]));
    let reference = protocol::ContextReferenceIdV1::new([9; 16]);
    assert_eq!(
        assembler.assemble(
            &AuthenticatedSessionV1 {
                principal: [4; 16],
                authority_context: [10; 16],
            },
            &request(reference),
            &profile(),
        ),
        Err(ContextRefusalV1::InvalidEvidence)
    );
}
