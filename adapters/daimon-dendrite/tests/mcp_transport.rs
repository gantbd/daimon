use daimon_dendrite::{
    ContextBindingV1, GroundingContextAssembler, McpEndpointV1, StreamableHttpClient,
    SurfaceQueryV1,
};
use daimon_host::{AuthenticatedSessionV1, ContextAssembler};
use daimon_protocol as protocol;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::Duration,
};

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
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
    let length = header
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    while request.len() < header_end + length {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        request.extend_from_slice(&buffer[..count]);
    }
    request
}

fn write_sse(stream: &mut TcpStream, value: serde_json::Value) {
    let event = format!("data: {}\n\n", serde_json::to_string(&value).unwrap());
    let chunked = format!("{:x}\r\n{}\r\n0\r\n\r\n", event.len(), event);
    let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    stream.write_all(header.as_bytes()).unwrap();
    stream.write_all(chunked.as_bytes()).unwrap();
}

#[test]
fn real_chunked_sse_mcp_calls_feed_digest_verified_grounding() {
    let authority = b"exact rune authority";
    let canonical = br#"{"version":2,"depth":"activated","entries":[{"id":"rule-1","kind":"guidance","text":"retain exact evidence"}]}"#;
    let grounding_digest: [u8; 32] = Sha256::digest(authority).into();
    let surface_digest: [u8; 32] = Sha256::digest(canonical).into();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        for call in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            send.send(request.clone()).unwrap();
            let body = request
                .windows(4)
                .position(|value| value == b"\r\n\r\n")
                .unwrap()
                + 4;
            let value: serde_json::Value = serde_json::from_slice(&request[body..]).unwrap();
            let id = value["id"].as_u64().unwrap();
            if call == 0 {
                assert_eq!(value["params"]["name"], "query_surface");
                write_sse(
                    &mut stream,
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{"type": "text", "text": "display only"}],
                            "structuredContent": {
                                "version": 2,
                                "target": "rune:rust-engineering",
                                "available_depths": ["ambient", "activated"],
                                "surface": {
                                    "depth": "activated",
                                    "entries": [{
                                        "id": "rule-1",
                                        "kind": "guidance",
                                        "text": "retain exact evidence"
                                    }]
                                },
                                "grounding_digest": format!("sha256:{}", hex(grounding_digest)),
                                "surface_digest": format!("sha256:{}", hex(surface_digest))
                            }
                        }
                    }),
                );
            } else {
                assert_eq!(value["params"]["name"], "read_ref");
                write_sse(
                    &mut stream,
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": String::from_utf8(authority.to_vec()).unwrap()
                            }]
                        }
                    }),
                );
            }
        }
    });

    let client = StreamableHttpClient::try_new(McpEndpointV1 {
        address,
        host_header: address.to_string(),
        bearer_token: Some(b"local-token".to_vec()),
        connect_timeout: Duration::from_secs(1),
        io_timeout: Duration::from_secs(1),
        max_request_bytes: 16 * 1024,
        max_response_bytes: 64 * 1024,
    })
    .unwrap();
    let reference = protocol::ContextReferenceIdV1::new([1; 16]);
    let mut assembler = GroundingContextAssembler::try_new(
        client,
        BTreeMap::from([(
            reference,
            ContextBindingV1::Dendrite {
                query: SurfaceQueryV1 {
                    load_id: "rust".into(),
                    target: "rune:rust-engineering".into(),
                    depth: protocol::GroundingDepthV1::Activated,
                },
                expected_grounding_digest: protocol::ContentDigestV1::new(grounding_digest),
                expected_surface_digest: protocol::ContentDigestV1::new(surface_digest),
            },
        )]),
        vec![protocol::ModelMessageV1 {
            role: protocol::MessageRoleV1::System,
            content: b"use grounding".to_vec(),
        }],
        8,
        4_096,
    )
    .unwrap();
    let request = protocol::ExecuteRequestV1 {
        execution_id: protocol::ExecutionIdV1::new([2; 16]),
        task_attempt: protocol::TaskAttemptRefV1 {
            task_key: [3; 16],
            task_incarnation: 1,
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
            max_tool_calls: 1,
            max_context_bytes: 4_096,
            max_output_bytes: 4_096,
        },
    };
    let input = assembler
        .assemble(
            &AuthenticatedSessionV1 {
                principal: [4; 16],
                authority_context: [7; 16],
            },
            &request,
            &protocol::ProviderProfileSnapshotV1 {
                provider: protocol::ProviderProfileIdV1::new([8; 16]),
                harness_profile: request.profile,
                wire: protocol::ProviderWireProfileV1::OpenAiChatCompletions,
                model: b"local".to_vec(),
                structured_tools: false,
                document_digest: protocol::ContentDigestV1::new([9; 32]),
            },
        )
        .unwrap();
    assert_eq!(input.context[0].bytes, canonical);
    assert_eq!(input.messages[1].content, canonical);
    assert_eq!(
        input.context[0].grounding.unwrap().surface_digest,
        protocol::ContentDigestV1::new(surface_digest)
    );
    for _ in 0..2 {
        let request = String::from_utf8(receive.recv().unwrap()).unwrap();
        assert!(request.starts_with("POST /mcp HTTP/1.1\r\n"));
        assert!(request.contains("Authorization: Bearer local-token\r\n"));
    }
}

#[test]
fn endpoint_debug_redacts_bearer_token() {
    let endpoint = McpEndpointV1 {
        address: "127.0.0.1:4499".parse().unwrap(),
        host_header: "127.0.0.1:4499".into(),
        bearer_token: Some(b"do-not-print".to_vec()),
        connect_timeout: Duration::from_secs(1),
        io_timeout: Duration::from_secs(1),
        max_request_bytes: 1,
        max_response_bytes: 1,
    };
    let debug = format!("{endpoint:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("do-not-print"));
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
