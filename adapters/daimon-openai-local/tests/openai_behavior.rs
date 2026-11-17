use daimon_host::{ModelProvider, ModelProviderOutcomeV1};
use daimon_openai_local::{
    EndpointV1, LocalProfileV1, OpenAiCompatibleProvider, ResponseModeV1, StaticProfileResolver,
    evidence_digest, profile_document_digest,
};
use daimon_protocol as protocol;
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::Duration,
};

fn profile(address: std::net::SocketAddr, mode: ResponseModeV1) -> LocalProfileV1 {
    let mut profile = LocalProfileV1 {
        snapshot: protocol::ProviderProfileSnapshotV1 {
            provider: protocol::ProviderProfileIdV1::new([1; 16]),
            harness_profile: protocol::HarnessProfileIdV1::new([2; 16]),
            wire: protocol::ProviderWireProfileV1::OpenAiChatCompletions,
            model: b"local-model".to_vec(),
            structured_tools: false,
            document_digest: protocol::ContentDigestV1::new([0; 32]),
        },
        endpoint: EndpointV1 {
            address,
            host_header: "127.0.0.1".into(),
            path: "/v1/chat/completions".into(),
            bearer_token: Some(b"local-secret".to_vec()),
            response_mode: mode,
            sampling_temperature_milli: 0,
            connect_timeout: Duration::from_secs(1),
            io_timeout: Duration::from_secs(1),
            max_request_bytes: 64 * 1024,
            max_response_bytes: 64 * 1024,
        },
    };
    profile.snapshot.document_digest =
        profile_document_digest(&profile.snapshot, &profile.endpoint);
    profile
}

fn invocation(snapshot: protocol::ProviderProfileSnapshotV1) -> protocol::ModelInvocationV1 {
    protocol::ModelInvocationV1 {
        execution_id: protocol::ExecutionIdV1::new([4; 16]),
        provider: snapshot,
        context: vec![protocol::ContextEvidenceV1 {
            reference: protocol::ContextReferenceIdV1::new([5; 16]),
            kind: protocol::ContextKindV1::DendriteGrounding,
            bytes: b"verified context".to_vec(),
            source_digest: protocol::ContentDigestV1::new([6; 32]),
            grounding: Some(protocol::GroundingEvidenceV1 {
                depth: protocol::GroundingDepthV1::Reference,
                grounding_digest: protocol::ContentDigestV1::new([7; 32]),
                surface_digest: protocol::ContentDigestV1::new([8; 32]),
            }),
        }],
        tools: vec![],
        continuation: None,
        messages: vec![protocol::ModelMessageV1 {
            role: protocol::MessageRoleV1::User,
            content: b"question".to_vec(),
        }],
        estimated_input_tokens: 2,
    }
}

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end;
    loop {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        request.extend_from_slice(&buffer[..count]);
        if let Some(index) = request.windows(4).position(|value| value == b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
    }
    let header = std::str::from_utf8(&request[..header_end]).unwrap();
    let content_length = header
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    while request.len() < header_end + content_length {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        request.extend_from_slice(&buffer[..count]);
    }
    request
}

fn server(response_body: Vec<u8>) -> (std::net::SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        send.send(read_request(&mut stream)).unwrap();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream.write_all(header.as_bytes()).unwrap();
        stream.write_all(&response_body).unwrap();
    });
    (address, receive)
}

#[test]
fn real_http_path_captures_usage_and_exact_evidence_without_retry_semantics() {
    let response = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3}
    }))
    .unwrap();
    let (address, request) = server(response);
    let profile = profile(address, ResponseModeV1::PlainText);
    let invocation = invocation(profile.snapshot.clone());
    let mut provider = OpenAiCompatibleProvider::try_new(&[profile]).unwrap();
    let ModelProviderOutcomeV1::Receipt(receipt) = provider.execute_model(&invocation) else {
        panic!("expected terminal receipt")
    };
    assert_eq!(receipt.input_tokens, 2);
    assert_eq!(receipt.output_tokens, 3);
    assert_eq!(receipt.output, b"answer");
    assert!(receipt.proposals.is_empty());
    assert_eq!(
        receipt.provider_document_digest,
        invocation.provider.document_digest
    );

    let request = String::from_utf8(request.recv().unwrap()).unwrap();
    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
    assert!(request.contains("Authorization: Bearer local-secret\r\n"));
    let body = request.split("\r\n\r\n").nth(1).unwrap();
    let body: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(body["model"], "local-model");
    assert_eq!(body["stream"], false);
    assert_eq!(body["temperature"], 0.0);
    assert!(body.get("tools").is_none());
}

#[test]
fn live_loopback_provider_returns_attributed_bounded_completion() {
    let Ok(model) = std::env::var("DAIMON_OPENAI_LIVE_MODEL") else {
        return;
    };
    let address = std::env::var("DAIMON_OPENAI_LIVE_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:11434".into())
        .parse()
        .unwrap();
    let mut profile = profile(address, ResponseModeV1::PlainText);
    profile.snapshot.model = model.into_bytes();
    profile.endpoint.bearer_token = None;
    profile.endpoint.connect_timeout = Duration::from_secs(5);
    profile.endpoint.io_timeout = Duration::from_secs(300);
    profile.endpoint.max_response_bytes = 1024 * 1024;
    profile.snapshot.document_digest =
        profile_document_digest(&profile.snapshot, &profile.endpoint);
    let invocation = invocation(profile.snapshot.clone());
    let mut provider = OpenAiCompatibleProvider::try_new(&[profile]).unwrap();

    let ModelProviderOutcomeV1::Receipt(receipt) = provider.execute_model(&invocation) else {
        panic!("live loopback provider did not return a terminal receipt")
    };
    assert!(!receipt.output.is_empty());
    assert!(receipt.input_tokens > 0);
    assert!(receipt.output_tokens > 0);
    assert!(receipt.proposals.is_empty());
    assert_eq!(
        receipt.provider_document_digest,
        invocation.provider.document_digest
    );
    assert_eq!(receipt.evidence_digest, evidence_digest(&invocation));
}

#[test]
fn strict_schema_content_becomes_typed_proposals_not_peer_receipts() {
    let envelope = json!({
        "output": "review complete",
        "proposals": [
            {
                "type": "agora_message",
                "room": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "reply_to": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "body": "reply"
            },
            {
                "type": "vellum_edit",
                "workspace": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                "document": "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
                "expected_revision": 9,
                "replacement": "edit"
            }
        ]
    });
    let response = serde_json::to_vec(&json!({
        "choices": [{
            "message": {"content": serde_json::to_string(&envelope).unwrap()},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 2, "completion_tokens": 8}
    }))
    .unwrap();
    let (address, request) = server(response);
    let profile = profile(address, ResponseModeV1::DaimonJsonSchema);
    let invocation = invocation(profile.snapshot.clone());
    let mut provider = OpenAiCompatibleProvider::try_new(&[profile]).unwrap();
    let ModelProviderOutcomeV1::Receipt(receipt) = provider.execute_model(&invocation) else {
        panic!("expected terminal receipt")
    };
    assert_eq!(receipt.output, b"review complete");
    assert_eq!(receipt.proposals.len(), 2);
    assert!(matches!(
        &receipt.proposals[0],
        protocol::OutputProposalV1::AgoraMessage(value) if value.room == [10; 16]
    ));
    assert!(matches!(
        &receipt.proposals[1],
        protocol::OutputProposalV1::VellumEdit(value)
            if value.document == [13; 16] && value.expected_revision == 9
    ));

    let request = String::from_utf8(request.recv().unwrap()).unwrap();
    let body: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["response_format"]["type"], "json_schema");
    assert_eq!(body["response_format"]["json_schema"]["strict"], true);
}

#[test]
fn native_openai_tool_calls_become_capability_bound_typed_proposals() {
    let capability = protocol::ToolCapabilityIdV1::new([10; 16]);
    let response = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": null,
                "tool_calls": [{
                    "id": "call_local_1",
                    "index": 0,
                    "type": "function",
                    "function": {
                        "name": "cap_0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                        "arguments": "{\"path\":\"README.md\",\"depth\":2}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 2, "completion_tokens": 4}
    }))
    .unwrap();
    let (address, request) = server(response);
    let mut profile = profile(address, ResponseModeV1::PlainText);
    profile.snapshot.structured_tools = true;
    profile.snapshot.document_digest =
        profile_document_digest(&profile.snapshot, &profile.endpoint);
    let mut invocation = invocation(profile.snapshot.clone());
    invocation.tools = vec![capability];
    let mut provider = OpenAiCompatibleProvider::try_new(&[profile]).unwrap();

    let ModelProviderOutcomeV1::Receipt(receipt) = provider.execute_model(&invocation) else {
        panic!("expected terminal receipt")
    };
    assert!(receipt.output.is_empty());
    assert!(matches!(
        receipt.proposals.as_slice(),
        [protocol::OutputProposalV1::ToolCall(call)]
            if call.request != [0; 16]
                && call.capability == capability
                && call.provider_correlation == b"call_local_1"
                && call.arguments == br#"{"depth":2,"path":"README.md"}"#
    ));

    let request = String::from_utf8(request.recv().unwrap()).unwrap();
    let body: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(
        body["tools"][0]["function"]["name"],
        "cap_0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
    );
    assert_eq!(
        body["tools"][0]["function"]["parameters"]["properties"],
        json!({})
    );
    assert_eq!(body["tools"][0]["function"]["parameters"]["type"], "object");
}

#[test]
fn native_tool_results_resume_with_matching_assistant_and_tool_messages() {
    let capability = protocol::ToolCapabilityIdV1::new([10; 16]);
    let response = serde_json::to_vec(&json!({
        "choices": [{
            "message": {"content": "README contents reviewed"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 9, "completion_tokens": 3}
    }))
    .unwrap();
    let (address, request) = server(response);
    let mut profile = profile(address, ResponseModeV1::PlainText);
    profile.snapshot.structured_tools = true;
    profile.snapshot.document_digest =
        profile_document_digest(&profile.snapshot, &profile.endpoint);
    let mut invocation = invocation(profile.snapshot.clone());
    invocation.tools = vec![capability];
    invocation.continuation = Some(protocol::ModelContinuationV1 {
        source_execution: protocol::ExecutionIdV1::new([3; 16]),
        source_output: Vec::new(),
        results: vec![protocol::ModelToolResultV1 {
            request: [11; 16],
            capability,
            provider_correlation: b"call_local_1".to_vec(),
            arguments: br#"{"path":"README.md"}"#.to_vec(),
            evidence_digest: protocol::ContentDigestV1::new([12; 32]),
            output_digest: protocol::ContentDigestV1::new([13; 32]),
            output: b"local tool output".to_vec(),
        }],
    });
    let mut provider = OpenAiCompatibleProvider::try_new(&[profile]).unwrap();

    let ModelProviderOutcomeV1::Receipt(receipt) = provider.execute_model(&invocation) else {
        panic!("expected terminal receipt")
    };
    assert_eq!(receipt.output, b"README contents reviewed");

    let request = String::from_utf8(request.recv().unwrap()).unwrap();
    let body: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages[1]["role"], "assistant");
    assert!(messages[1].get("content").is_none());
    assert_eq!(messages[1]["tool_calls"][0]["id"], "call_local_1");
    assert_eq!(messages[1]["tool_calls"][0]["type"], "function");
    assert_eq!(
        messages[1]["tool_calls"][0]["function"]["name"],
        "cap_0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
    );
    assert_eq!(
        messages[1]["tool_calls"][0]["function"]["arguments"],
        r#"{"path":"README.md"}"#
    );
    assert_eq!(messages[2]["role"], "tool");
    assert_eq!(messages[2]["tool_call_id"], "call_local_1");
    assert_eq!(messages[2]["content"], "local tool output");
}

#[test]
fn json_looking_plain_text_never_becomes_a_tool_call() {
    let content = r#"{"tool":"cap_0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","arguments":{}}"#;
    let response = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3}
    }))
    .unwrap();
    let (address, request) = server(response);
    let profile = profile(address, ResponseModeV1::PlainText);
    let invocation = invocation(profile.snapshot.clone());
    let mut provider = OpenAiCompatibleProvider::try_new(&[profile]).unwrap();
    let ModelProviderOutcomeV1::Receipt(receipt) = provider.execute_model(&invocation) else {
        panic!("expected terminal receipt")
    };
    assert_eq!(receipt.output, content.as_bytes());
    assert!(receipt.proposals.is_empty());

    let request = String::from_utf8(request.recv().unwrap()).unwrap();
    let body: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert!(body.get("tools").is_none());
}

#[test]
fn missing_usage_is_outcome_unknown_instead_of_unbudgeted_success() {
    let response = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}]
    }))
    .unwrap();
    let (address, _request) = server(response);
    let profile = profile(address, ResponseModeV1::PlainText);
    let invocation = invocation(profile.snapshot.clone());
    let mut provider = OpenAiCompatibleProvider::try_new(&[profile]).unwrap();
    assert_eq!(
        provider.execute_model(&invocation),
        ModelProviderOutcomeV1::OutcomeUnknown
    );
}

#[test]
fn frozen_profile_digest_covers_non_secret_endpoint_policy_but_not_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = profile(listener.local_addr().unwrap(), ResponseModeV1::PlainText);
    let mut credential_rotation = profile.clone();
    credential_rotation.endpoint.bearer_token = Some(b"rotated-secret".to_vec());
    assert_eq!(
        profile_document_digest(&credential_rotation.snapshot, &credential_rotation.endpoint),
        profile.snapshot.document_digest
    );
    assert!(StaticProfileResolver::try_new(&[credential_rotation]).is_some());

    let mut sampling_drift = profile.clone();
    sampling_drift.endpoint.sampling_temperature_milli = 700;
    assert!(StaticProfileResolver::try_new(&[sampling_drift]).is_none());

    let mut invalid_sampling = profile.clone();
    invalid_sampling.endpoint.sampling_temperature_milli = 2_001;
    invalid_sampling.snapshot.document_digest =
        profile_document_digest(&invalid_sampling.snapshot, &invalid_sampling.endpoint);
    assert!(StaticProfileResolver::try_new(&[invalid_sampling]).is_none());

    let mut path_drift = profile;
    path_drift.endpoint.path = "/v1/other".into();
    assert!(StaticProfileResolver::try_new(&[path_drift]).is_none());
}

#[test]
fn evidence_digest_binds_exact_messages_context_and_profile() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = profile(listener.local_addr().unwrap(), ResponseModeV1::PlainText);
    let baseline = invocation(profile.snapshot);
    let digest = evidence_digest(&baseline);

    let mut changed_message = baseline.clone();
    changed_message.messages[0].content.push(b'!');
    assert_ne!(evidence_digest(&changed_message), digest);

    let mut changed_context = baseline.clone();
    changed_context.context[0].bytes.push(b'!');
    assert_ne!(evidence_digest(&changed_context), digest);

    let mut changed_profile = baseline;
    changed_profile.provider.document_digest = protocol::ContentDigestV1::new([99; 32]);
    assert_ne!(evidence_digest(&changed_profile), digest);
}

#[test]
fn endpoint_debug_redacts_bearer_token() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = profile(listener.local_addr().unwrap(), ResponseModeV1::PlainText).endpoint;
    let debug = format!("{endpoint:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("local-secret"));
}
