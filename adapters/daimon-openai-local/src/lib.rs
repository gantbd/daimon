//! One-shot OpenAI-compatible adapter for loopback-hosted models.
//!
//! The adapter owns HTTP wire compatibility only. It does not retry, redirect,
//! select a fallback provider, or submit Agora/Vellum effects.

#![forbid(unsafe_code)]

use daimon_host::{
    AuthenticatedSessionV1, ModelProvider, ModelProviderOutcomeV1, ProfileRefusalV1,
    ProviderProfileResolver,
};
use daimon_protocol as protocol;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseModeV1 {
    PlainText,
    DaimonJsonSchema,
}

#[derive(Clone, Eq, PartialEq)]
pub struct EndpointV1 {
    pub address: SocketAddr,
    pub host_header: String,
    pub path: String,
    pub bearer_token: Option<Vec<u8>>,
    pub response_mode: ResponseModeV1,
    /// Sampling temperature in thousandths, included in the profile digest.
    pub sampling_temperature_milli: u16,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}

impl std::fmt::Debug for EndpointV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EndpointV1")
            .field("address", &self.address)
            .field("host_header", &self.host_header)
            .field("path", &self.path)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .field("response_mode", &self.response_mode)
            .field(
                "sampling_temperature_milli",
                &self.sampling_temperature_milli,
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl EndpointV1 {
    pub fn validate(&self) -> bool {
        self.address.ip().is_loopback()
            && !self.host_header.is_empty()
            && self.host_header.is_ascii()
            && !self.host_header.contains(['\r', '\n'])
            && self.path.starts_with('/')
            && self.path.is_ascii()
            && !self.path.contains(['\r', '\n', ' '])
            && self
                .bearer_token
                .as_ref()
                .is_none_or(|token| !token.is_empty() && token.iter().all(u8::is_ascii_graphic))
            && !self.connect_timeout.is_zero()
            && !self.io_timeout.is_zero()
            && self.sampling_temperature_milli <= 2_000
            && self.max_request_bytes != 0
            && self.max_response_bytes != 0
    }
}

#[derive(Clone)]
pub struct LocalProfileV1 {
    pub snapshot: protocol::ProviderProfileSnapshotV1,
    pub endpoint: EndpointV1,
}

#[derive(Clone, Default)]
pub struct StaticProfileResolver {
    by_harness: BTreeMap<protocol::HarnessProfileIdV1, protocol::ProviderProfileSnapshotV1>,
}

impl StaticProfileResolver {
    pub fn try_new(profiles: &[LocalProfileV1]) -> Option<Self> {
        let mut by_harness = BTreeMap::new();
        for profile in profiles {
            if !profile.endpoint.validate()
                || profile.snapshot.model.is_empty()
                || profile.snapshot.document_digest
                    != profile_document_digest(&profile.snapshot, &profile.endpoint)
                || by_harness
                    .insert(profile.snapshot.harness_profile, profile.snapshot.clone())
                    .is_some()
            {
                return None;
            }
        }
        Some(Self { by_harness })
    }
}

impl ProviderProfileResolver for StaticProfileResolver {
    fn resolve_profile(
        &mut self,
        _session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
    ) -> Result<protocol::ProviderProfileSnapshotV1, ProfileRefusalV1> {
        self.by_harness
            .get(&request.profile)
            .cloned()
            .ok_or(ProfileRefusalV1::Unknown)
    }
}

pub struct OpenAiCompatibleProvider {
    endpoints: BTreeMap<protocol::ProviderProfileIdV1, EndpointV1>,
}

impl OpenAiCompatibleProvider {
    pub fn try_new(profiles: &[LocalProfileV1]) -> Option<Self> {
        let mut endpoints = BTreeMap::new();
        for profile in profiles {
            if !profile.endpoint.validate()
                || profile.snapshot.document_digest
                    != profile_document_digest(&profile.snapshot, &profile.endpoint)
                || endpoints
                    .insert(profile.snapshot.provider, profile.endpoint.clone())
                    .is_some()
            {
                return None;
            }
        }
        Some(Self { endpoints })
    }
}

/// Canonical digest of every non-secret profile selection field. The bearer
/// token is intentionally excluded and never enters a protocol snapshot.
pub fn profile_document_digest(
    snapshot: &protocol::ProviderProfileSnapshotV1,
    endpoint: &EndpointV1,
) -> protocol::ContentDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"daimon-openai-local-profile-v1\0");
    hash.update(snapshot.provider.into_bytes());
    hash.update(snapshot.harness_profile.into_bytes());
    hash.update([match snapshot.wire {
        protocol::ProviderWireProfileV1::OpenAiChatCompletions => 0,
    }]);
    hash.update(
        u64::try_from(snapshot.model.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.update(&snapshot.model);
    hash.update([u8::from(snapshot.structured_tools)]);
    match endpoint.address.ip() {
        std::net::IpAddr::V4(address) => {
            hash.update([4]);
            hash.update(address.octets());
        }
        std::net::IpAddr::V6(address) => {
            hash.update([6]);
            hash.update(address.octets());
        }
    }
    hash.update(endpoint.address.port().to_be_bytes());
    hash_len_bytes(&mut hash, endpoint.host_header.as_bytes());
    hash_len_bytes(&mut hash, endpoint.path.as_bytes());
    hash.update([match endpoint.response_mode {
        ResponseModeV1::PlainText => 0,
        ResponseModeV1::DaimonJsonSchema => 1,
    }]);
    hash.update(endpoint.sampling_temperature_milli.to_be_bytes());
    hash_duration(&mut hash, endpoint.connect_timeout);
    hash_duration(&mut hash, endpoint.io_timeout);
    hash.update(
        u64::try_from(endpoint.max_request_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.update(
        u64::try_from(endpoint.max_response_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    protocol::ContentDigestV1::new(hash.finalize().into())
}

fn hash_len_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(bytes);
}

fn hash_duration(hash: &mut Sha256, duration: Duration) {
    hash.update(duration.as_secs().to_be_bytes());
    hash.update(duration.subsec_nanos().to_be_bytes());
}

impl ModelProvider for OpenAiCompatibleProvider {
    fn execute_model(
        &mut self,
        invocation: &protocol::ModelInvocationV1,
    ) -> ModelProviderOutcomeV1 {
        let Some(endpoint) = self.endpoints.get(&invocation.provider.provider) else {
            return ModelProviderOutcomeV1::OutcomeUnknown;
        };
        match execute_once(endpoint, invocation) {
            Ok(receipt) => ModelProviderOutcomeV1::Receipt(receipt),
            Err(()) => ModelProviderOutcomeV1::OutcomeUnknown,
        }
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
    stream: bool,
    temperature: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<ToolDefinition>>,
}

#[derive(Serialize)]
struct ChatMessage {
    role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<RequestToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize)]
struct RequestToolCall {
    id: String,
    r#type: &'static str,
    function: RequestToolFunction,
}

#[derive(Serialize)]
struct RequestToolFunction {
    name: String,
    arguments: String,
}

#[derive(Serialize)]
struct ResponseFormat {
    r#type: &'static str,
    json_schema: JsonSchema,
}

#[derive(Serialize)]
struct JsonSchema {
    name: &'static str,
    strict: bool,
    schema: serde_json::Value,
}

#[derive(Serialize)]
struct ToolDefinition {
    r#type: &'static str,
    function: ToolFunctionDefinition,
}

#[derive(Serialize)]
struct ToolFunctionDefinition {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ResponseToolCall>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseToolCall {
    id: String,
    #[serde(default, rename = "index")]
    _index: Option<u64>,
    r#type: String,
    function: ResponseToolFunction,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseToolFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct Usage {
    prompt_tokens: u64,
    completion_tokens: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    output: String,
    #[serde(default)]
    proposals: Vec<Proposal>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Proposal {
    AgoraMessage {
        room: String,
        reply_to: String,
        body: String,
    },
    VellumEdit {
        workspace: String,
        document: String,
        expected_revision: u64,
        replacement: String,
    },
}

fn execute_once(
    endpoint: &EndpointV1,
    invocation: &protocol::ModelInvocationV1,
) -> Result<protocol::ModelProviderReceiptV1, ()> {
    let model = std::str::from_utf8(&invocation.provider.model).map_err(|_| ())?;
    let mut messages = invocation
        .messages
        .iter()
        .map(|message| {
            Ok(ChatMessage {
                role: match message.role {
                    protocol::MessageRoleV1::System => "system",
                    protocol::MessageRoleV1::User => "user",
                    protocol::MessageRoleV1::Assistant => "assistant",
                    protocol::MessageRoleV1::Tool => "tool",
                },
                content: Some(
                    std::str::from_utf8(&message.content)
                        .map_err(|_| ())?
                        .to_owned(),
                ),
                tool_calls: None,
                tool_call_id: None,
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    if let Some(continuation) = &invocation.continuation {
        if continuation.results.is_empty() {
            return Err(());
        }
        let mut calls = Vec::new();
        calls
            .try_reserve(continuation.results.len())
            .map_err(|_| ())?;
        for result in &continuation.results {
            let id = std::str::from_utf8(&result.provider_correlation)
                .map_err(|_| ())?
                .to_owned();
            let arguments = std::str::from_utf8(&result.arguments)
                .map_err(|_| ())?
                .to_owned();
            calls.push(RequestToolCall {
                id,
                r#type: "function",
                function: RequestToolFunction {
                    name: tool_name(result.capability),
                    arguments,
                },
            });
        }
        messages.push(ChatMessage {
            role: "assistant",
            content: if continuation.source_output.is_empty() {
                None
            } else {
                Some(
                    std::str::from_utf8(&continuation.source_output)
                        .map_err(|_| ())?
                        .to_owned(),
                )
            },
            tool_calls: Some(calls),
            tool_call_id: None,
        });
        for result in &continuation.results {
            messages.push(ChatMessage {
                role: "tool",
                content: Some(tool_output_content(&result.output)?),
                tool_calls: None,
                tool_call_id: Some(
                    std::str::from_utf8(&result.provider_correlation)
                        .map_err(|_| ())?
                        .to_owned(),
                ),
            });
        }
    }
    let response_format =
        (endpoint.response_mode == ResponseModeV1::DaimonJsonSchema).then(strict_response_format);
    let tools = (invocation.provider.structured_tools && !invocation.tools.is_empty()).then(|| {
        invocation
            .tools
            .iter()
            .map(|capability| ToolDefinition {
                r#type: "function",
                function: ToolFunctionDefinition {
                    name: tool_name(*capability),
                    description: "Deployment-authorized structured capability".into(),
                    parameters: serde_json::json!({
                        "type": "object",
                        "properties": {},
                        "additionalProperties": true
                    }),
                },
            })
            .collect()
    });
    let body = serde_json::to_vec(&ChatRequest {
        model,
        messages,
        stream: false,
        temperature: f64::from(endpoint.sampling_temperature_milli) / 1_000.0,
        response_format,
        tools,
    })
    .map_err(|_| ())?;
    if body.len() > endpoint.max_request_bytes {
        return Err(());
    }
    let response = post_once(endpoint, &body)?;
    let decoded: ChatResponse = serde_json::from_slice(&response).map_err(|_| ())?;
    let usage = decoded.usage.ok_or(())?;
    let choice = decoded.choices.into_iter().next().ok_or(())?;
    let content = choice.message.content.unwrap_or_default();
    if content.is_empty() && choice.message.tool_calls.is_empty() {
        return Err(());
    }
    let has_tool_calls = !choice.message.tool_calls.is_empty();
    let (output, mut proposals) = match endpoint.response_mode {
        _ if has_tool_calls && content.is_empty() => (Vec::new(), Vec::new()),
        ResponseModeV1::PlainText => (content.into_bytes(), Vec::new()),
        ResponseModeV1::DaimonJsonSchema => {
            let envelope: Envelope = serde_json::from_str(&content).map_err(|_| ())?;
            let proposals = envelope
                .proposals
                .into_iter()
                .map(protocol_proposal)
                .collect::<Result<Vec<_>, ()>>()?;
            (envelope.output.into_bytes(), proposals)
        }
    };
    if has_tool_calls {
        if !invocation.provider.structured_tools || invocation.tools.is_empty() {
            return Err(());
        }
        for call in choice.message.tool_calls {
            if call.r#type != "function" || call.id.is_empty() || call.id.len() > 1_024 {
                return Err(());
            }
            let capability = decode_tool_name(&call.function.name)?;
            if !invocation.tools.contains(&capability) {
                return Err(());
            }
            let arguments: serde_json::Value =
                serde_json::from_str(&call.function.arguments).map_err(|_| ())?;
            if !arguments.is_object() {
                return Err(());
            }
            let arguments = serde_json::to_vec(&arguments).map_err(|_| ())?;
            let mut hash = Sha256::new();
            hash.update(b"daimon-tool-call-v1\0");
            hash.update(invocation.execution_id.into_bytes());
            hash_len_bytes(&mut hash, call.id.as_bytes());
            let digest = hash.finalize();
            let mut request = [0_u8; 16];
            request.copy_from_slice(&digest[..16]);
            proposals.push(protocol::OutputProposalV1::ToolCall(
                protocol::ToolCallProposalV1 {
                    request,
                    capability,
                    provider_correlation: call.id.into_bytes(),
                    arguments,
                },
            ));
        }
    }
    Ok(protocol::ModelProviderReceiptV1 {
        execution_id: invocation.execution_id,
        provider_document_digest: invocation.provider.document_digest,
        evidence_digest: evidence_digest(invocation),
        disposition: match choice.finish_reason.as_deref() {
            Some("length") => protocol::ExecutionDispositionV1::TimedOut,
            Some("stop" | "tool_calls") | None => protocol::ExecutionDispositionV1::Completed,
            Some(_) => protocol::ExecutionDispositionV1::Failed,
        },
        input_tokens: usage.prompt_tokens,
        output_tokens: usage.completion_tokens,
        output,
        proposals,
    })
}

fn tool_name(capability: protocol::ToolCapabilityIdV1) -> String {
    let mut name = String::with_capacity(37);
    name.push_str("cap_");
    for byte in capability.into_bytes() {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name
}

fn tool_output_content(output: &[u8]) -> Result<String, ()> {
    if let Ok(text) = std::str::from_utf8(output) {
        return Ok(text.to_owned());
    }
    let mut encoded = String::new();
    encoded
        .try_reserve(output.len().saturating_mul(2))
        .map_err(|_| ())?;
    for byte in output {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").map_err(|_| ())?;
    }
    serde_json::to_string(&serde_json::json!({
        "encoding": "hex",
        "data": encoded
    }))
    .map_err(|_| ())
}

fn decode_tool_name(value: &str) -> Result<protocol::ToolCapabilityIdV1, ()> {
    let encoded = value.strip_prefix("cap_").ok_or(())?;
    Ok(protocol::ToolCapabilityIdV1::new(decode_id(encoded)?))
}

fn strict_response_format() -> ResponseFormat {
    ResponseFormat {
        r#type: "json_schema",
        json_schema: JsonSchema {
            name: "daimon_result_v1",
            strict: true,
            schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["output", "proposals"],
                "properties": {
                    "output": {"type": "string"},
                    "proposals": {
                        "type": "array",
                        "items": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["type", "room", "reply_to", "body"],
                                    "properties": {
                                        "type": {"const": "agora_message"},
                                        "room": {"type": "string", "pattern": "^[0-9a-fA-F]{32}$"},
                                        "reply_to": {"type": "string", "pattern": "^[0-9a-fA-F]{32}$"},
                                        "body": {"type": "string"}
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["type", "workspace", "document", "expected_revision", "replacement"],
                                    "properties": {
                                        "type": {"const": "vellum_edit"},
                                        "workspace": {"type": "string", "pattern": "^[0-9a-fA-F]{32}$"},
                                        "document": {"type": "string", "pattern": "^[0-9a-fA-F]{32}$"},
                                        "expected_revision": {"type": "integer", "minimum": 0},
                                        "replacement": {"type": "string"}
                                    }
                                }
                            ]
                        }
                    }
                }
            }),
        },
    }
}

fn protocol_proposal(value: Proposal) -> Result<protocol::OutputProposalV1, ()> {
    Ok(match value {
        Proposal::AgoraMessage {
            room,
            reply_to,
            body,
        } => protocol::OutputProposalV1::AgoraMessage(protocol::AgoraMessageProposalV1 {
            room: decode_id(&room)?,
            reply_to: decode_id(&reply_to)?,
            body: body.into_bytes(),
        }),
        Proposal::VellumEdit {
            workspace,
            document,
            expected_revision,
            replacement,
        } => protocol::OutputProposalV1::VellumEdit(protocol::VellumEditProposalV1 {
            workspace: decode_id(&workspace)?,
            document: decode_id(&document)?,
            expected_revision,
            replacement: replacement.into_bytes(),
        }),
    })
}

fn decode_id(value: &str) -> Result<[u8; 16], ()> {
    if value.len() != 32 || !value.is_ascii() {
        return Err(());
    }
    let mut bytes = [0_u8; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
}

/// Canonical attribution for the exact provider profile, messages and context
/// admitted to one model invocation. Credentials are excluded by the profile
/// document digest.
pub fn evidence_digest(invocation: &protocol::ModelInvocationV1) -> protocol::ContentDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"daimon-model-evidence-v2\0");
    hash.update(invocation.execution_id.into_bytes());
    hash.update(invocation.provider.document_digest.into_bytes());
    hash.update(
        u64::try_from(invocation.messages.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for message in &invocation.messages {
        hash.update([match message.role {
            protocol::MessageRoleV1::System => 0,
            protocol::MessageRoleV1::User => 1,
            protocol::MessageRoleV1::Assistant => 2,
            protocol::MessageRoleV1::Tool => 3,
        }]);
        hash.update(
            u64::try_from(message.content.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(&message.content);
    }
    match &invocation.continuation {
        None => hash.update([0]),
        Some(continuation) => {
            hash.update([1]);
            hash.update(continuation.source_execution.into_bytes());
            hash_len_bytes(&mut hash, &continuation.source_output);
            hash.update(
                u64::try_from(continuation.results.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            for result in &continuation.results {
                hash.update(result.request);
                hash.update(result.capability.into_bytes());
                hash_len_bytes(&mut hash, &result.provider_correlation);
                hash_len_bytes(&mut hash, &result.arguments);
                hash.update(result.evidence_digest.into_bytes());
                hash.update(result.output_digest.into_bytes());
                hash_len_bytes(&mut hash, &result.output);
            }
        }
    }
    hash.update(
        u64::try_from(invocation.context.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for evidence in &invocation.context {
        hash.update(evidence.reference.into_bytes());
        hash.update([match evidence.kind {
            protocol::ContextKindV1::AgoraMessage => 0,
            protocol::ContextKindV1::ChronosWork => 1,
            protocol::ContextKindV1::VellumDocument => 2,
            protocol::ContextKindV1::DendriteGrounding => 3,
        }]);
        hash.update(evidence.source_digest.into_bytes());
        hash.update(
            u64::try_from(evidence.bytes.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(&evidence.bytes);
        if let Some(grounding) = evidence.grounding {
            hash.update([1]);
            hash.update([match grounding.depth {
                protocol::GroundingDepthV1::Ambient => 0,
                protocol::GroundingDepthV1::Activated => 1,
                protocol::GroundingDepthV1::Reference => 2,
            }]);
            hash.update(grounding.grounding_digest.into_bytes());
            hash.update(grounding.surface_digest.into_bytes());
        } else {
            hash.update([0]);
        }
    }
    protocol::ContentDigestV1::new(hash.finalize().into())
}

fn post_once(endpoint: &EndpointV1, body: &[u8]) -> Result<Vec<u8>, ()> {
    let mut stream =
        TcpStream::connect_timeout(&endpoint.address, endpoint.connect_timeout).map_err(|_| ())?;
    stream
        .set_read_timeout(Some(endpoint.io_timeout))
        .and_then(|()| stream.set_write_timeout(Some(endpoint.io_timeout)))
        .map_err(|_| ())?;
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n",
        endpoint.path,
        endpoint.host_header,
        body.len()
    )
    .into_bytes();
    if let Some(token) = &endpoint.bearer_token {
        head.extend_from_slice(b"Authorization: Bearer ");
        head.extend_from_slice(token);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    if head
        .len()
        .checked_add(body.len())
        .is_none_or(|length| length > endpoint.max_request_bytes)
    {
        return Err(());
    }
    stream.write_all(&head).map_err(|_| ())?;
    stream.write_all(body).map_err(|_| ())?;
    stream.flush().map_err(|_| ())?;

    let maximum = u64::try_from(endpoint.max_response_bytes)
        .map_err(|_| ())?
        .checked_add(1)
        .ok_or(())?;
    let mut response = Vec::new();
    stream
        .take(maximum)
        .read_to_end(&mut response)
        .map_err(|_| ())?;
    if response.len() > endpoint.max_response_bytes {
        return Err(());
    }
    decode_http_response(&response, endpoint.max_response_bytes)
}

fn decode_http_response(response: &[u8], maximum: usize) -> Result<Vec<u8>, ()> {
    let separator = response
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .ok_or(())?;
    let head = std::str::from_utf8(&response[..separator]).map_err(|_| ())?;
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(())?;
    let mut status_fields = status.split_ascii_whitespace();
    if status_fields.next() != Some("HTTP/1.1")
        || status_fields
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            != Some(200)
    {
        return Err(());
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(())?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length
                .replace(value.parse::<usize>().map_err(|_| ())?)
                .is_some()
            {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
            if !chunked {
                return Err(());
            }
        }
    }
    let body = &response[separator + 4..];
    if chunked {
        decode_chunks(body, maximum)
    } else if let Some(length) = content_length {
        if length > maximum || body.len() != length {
            return Err(());
        }
        Ok(body.to_vec())
    } else if body.len() <= maximum {
        Ok(body.to_vec())
    } else {
        Err(())
    }
}

fn decode_chunks(mut input: &[u8], maximum: usize) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|value| value == b"\r\n")
            .ok_or(())?;
        let line = std::str::from_utf8(&input[..line_end]).map_err(|_| ())?;
        let size = usize::from_str_radix(line.split(';').next().ok_or(())?, 16).map_err(|_| ())?;
        input = &input[line_end + 2..];
        if size == 0 {
            return input.starts_with(b"\r\n").then_some(output).ok_or(());
        }
        if size > maximum.saturating_sub(output.len()) || input.len() < size + 2 {
            return Err(());
        }
        output.extend_from_slice(&input[..size]);
        if &input[size..size + 2] != b"\r\n" {
            return Err(());
        }
        input = &input[size + 2..];
    }
}
