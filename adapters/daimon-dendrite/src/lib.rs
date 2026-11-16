//! Optional Dendrite grounding with exact authority and projection verification.
//!
//! The Dendrite client port carries only its consumer-neutral load, target and
//! depth vocabulary. Daimon execution, provider and checkpoint identities are
//! deliberately absent from that interface.

#![forbid(unsafe_code)]

use daimon_host::{
    AssembledModelInputV1, AuthenticatedSessionV1, ContextAssembler, ContextRefusalV1,
};
use daimon_protocol as protocol;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

#[derive(Clone, Eq, PartialEq)]
pub struct McpEndpointV1 {
    pub address: SocketAddr,
    pub host_header: String,
    pub bearer_token: Option<Vec<u8>>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}

impl std::fmt::Debug for McpEndpointV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpEndpointV1")
            .field("address", &self.address)
            .field("host_header", &self.host_header)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl McpEndpointV1 {
    pub fn validate(&self) -> bool {
        self.address.ip().is_loopback()
            && !self.host_header.is_empty()
            && self.host_header.is_ascii()
            && !self.host_header.contains(['\r', '\n'])
            && self
                .bearer_token
                .as_ref()
                .is_none_or(|token| !token.is_empty() && token.iter().all(u8::is_ascii_graphic))
            && !self.connect_timeout.is_zero()
            && !self.io_timeout.is_zero()
            && self.max_request_bytes != 0
            && self.max_response_bytes != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpClientErrorV1 {
    InvalidConfiguration,
    Limit,
    Transport,
    Http,
    Protocol,
    Tool,
}

/// Minimal bounded MCP Streamable HTTP client for Dendrite's two grounding
/// operations. Each call is one loopback request; no retry or redirect occurs.
pub struct StreamableHttpClient {
    endpoint: McpEndpointV1,
    next_request: u64,
}

impl StreamableHttpClient {
    pub fn try_new(endpoint: McpEndpointV1) -> Result<Self, McpClientErrorV1> {
        if !endpoint.validate() {
            return Err(McpClientErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            endpoint,
            next_request: 1,
        })
    }

    pub fn endpoint(&self) -> &McpEndpointV1 {
        &self.endpoint
    }

    fn call(
        &mut self,
        name: &'static str,
        arguments: serde_json::Value,
    ) -> Result<ToolResult, McpClientErrorV1> {
        let id = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or(McpClientErrorV1::Limit)?;
        let body = serde_json::to_vec(&JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: "tools/call",
            params: ToolCall { name, arguments },
        })
        .map_err(|_| McpClientErrorV1::Protocol)?;
        if body.len() > self.endpoint.max_request_bytes {
            return Err(McpClientErrorV1::Limit);
        }
        let response = post_mcp(&self.endpoint, &body)?;
        let payload = extract_sse_json(&response)?;
        let decoded: JsonRpcResponse =
            serde_json::from_slice(payload).map_err(|_| McpClientErrorV1::Protocol)?;
        if decoded.error.is_some() || decoded.id != Some(id) {
            return Err(McpClientErrorV1::Protocol);
        }
        let result = decoded.result.ok_or(McpClientErrorV1::Protocol)?;
        if result.is_error {
            return Err(McpClientErrorV1::Tool);
        }
        Ok(result)
    }
}

impl DendriteClient for StreamableHttpClient {
    type Error = McpClientErrorV1;

    fn query_surface(&mut self, query: &SurfaceQueryV1) -> Result<SurfaceResponseV1, Self::Error> {
        let result = self.call(
            "query_surface",
            serde_json::json!({
                "load_id": query.load_id,
                "target": query.target,
                "depth": depth_name(query.depth),
            }),
        )?;
        let content: SurfaceStructured = serde_json::from_value(
            result
                .structured_content
                .ok_or(McpClientErrorV1::Protocol)?,
        )
        .map_err(|_| McpClientErrorV1::Protocol)?;
        Ok(SurfaceResponseV1 {
            version: content.version,
            target: content.target,
            depth: parse_depth(&content.surface.depth)?,
            entries: content
                .surface
                .entries
                .into_iter()
                .map(|entry| SurfaceEntryV1 {
                    id: entry.id,
                    kind: entry.kind,
                    text: entry.text,
                })
                .collect(),
            grounding_digest: parse_digest(&content.grounding_digest)?,
            surface_digest: parse_digest(&content.surface_digest)?,
        })
    }

    fn read_ref(&mut self, load_id: &str, target: &str) -> Result<Vec<u8>, Self::Error> {
        let result = self.call(
            "read_ref",
            serde_json::json!({"load_id": load_id, "target": target}),
        )?;
        let first = result
            .content
            .into_iter()
            .next()
            .ok_or(McpClientErrorV1::Protocol)?;
        if first.kind != "text" {
            return Err(McpClientErrorV1::Protocol);
        }
        Ok(first.text.into_bytes())
    }
}

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: ToolCall,
}

#[derive(Serialize)]
struct ToolCall {
    name: &'static str,
    arguments: serde_json::Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    id: Option<u64>,
    result: Option<ToolResult>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToolResult {
    #[serde(default)]
    is_error: bool,
    #[serde(default)]
    structured_content: Option<serde_json::Value>,
    #[serde(default)]
    content: Vec<ToolContent>,
}

#[derive(Deserialize)]
struct ToolContent {
    #[serde(rename = "type")]
    kind: String,
    text: String,
}

#[derive(Deserialize)]
struct SurfaceStructured {
    version: u64,
    target: String,
    surface: StructuredSurface,
    grounding_digest: String,
    surface_digest: String,
}

#[derive(Deserialize)]
struct StructuredSurface {
    depth: String,
    entries: Vec<StructuredEntry>,
}

#[derive(Deserialize)]
struct StructuredEntry {
    #[serde(default)]
    id: Option<String>,
    kind: String,
    text: String,
}

fn post_mcp(endpoint: &McpEndpointV1, body: &[u8]) -> Result<Vec<u8>, McpClientErrorV1> {
    let mut stream = TcpStream::connect_timeout(&endpoint.address, endpoint.connect_timeout)
        .map_err(|_| McpClientErrorV1::Transport)?;
    stream
        .set_read_timeout(Some(endpoint.io_timeout))
        .and_then(|()| stream.set_write_timeout(Some(endpoint.io_timeout)))
        .map_err(|_| McpClientErrorV1::Transport)?;
    let authorization = endpoint
        .bearer_token
        .as_ref()
        .map_or_else(String::new, |token| {
            format!(
                "Authorization: Bearer {}\r\n",
                String::from_utf8_lossy(token)
            )
        });
    let header = format!(
        "POST /mcp HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.host_header,
        authorization,
        body.len()
    );
    if header.len() > endpoint.max_request_bytes.saturating_sub(body.len()) {
        return Err(McpClientErrorV1::Limit);
    }
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|_| McpClientErrorV1::Transport)?;
    let mut response = Vec::new();
    stream
        .take(
            u64::try_from(endpoint.max_response_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut response)
        .map_err(|_| McpClientErrorV1::Transport)?;
    if response.len() > endpoint.max_response_bytes {
        return Err(McpClientErrorV1::Limit);
    }
    parse_http_response(&response, endpoint.max_response_bytes)
}

fn parse_http_response(response: &[u8], maximum: usize) -> Result<Vec<u8>, McpClientErrorV1> {
    let header_end = response
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or(McpClientErrorV1::Http)?;
    let header =
        std::str::from_utf8(&response[..header_end]).map_err(|_| McpClientErrorV1::Http)?;
    let mut lines = header.split("\r\n");
    let status = lines.next().ok_or(McpClientErrorV1::Http)?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        return Err(McpClientErrorV1::Http);
    }
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    if chunked {
        decode_chunked(&response[header_end..], maximum)
    } else {
        Ok(response[header_end..].to_vec())
    }
}

fn decode_chunked(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, McpClientErrorV1> {
    let mut position = 0usize;
    let mut output = Vec::new();
    loop {
        let line_end = bytes[position..]
            .windows(2)
            .position(|value| value == b"\r\n")
            .map(|index| position + index)
            .ok_or(McpClientErrorV1::Http)?;
        let size_text =
            std::str::from_utf8(&bytes[position..line_end]).map_err(|_| McpClientErrorV1::Http)?;
        let size_text = size_text.split(';').next().ok_or(McpClientErrorV1::Http)?;
        let size = usize::from_str_radix(size_text, 16).map_err(|_| McpClientErrorV1::Http)?;
        position = line_end.checked_add(2).ok_or(McpClientErrorV1::Limit)?;
        if size == 0 {
            return Ok(output);
        }
        let end = position.checked_add(size).ok_or(McpClientErrorV1::Limit)?;
        if end.checked_add(2).ok_or(McpClientErrorV1::Limit)? > bytes.len()
            || bytes.get(end..end + 2) != Some(b"\r\n")
            || size > maximum.saturating_sub(output.len())
        {
            return Err(McpClientErrorV1::Limit);
        }
        output.extend_from_slice(&bytes[position..end]);
        position = end + 2;
    }
}

fn extract_sse_json(bytes: &[u8]) -> Result<&[u8], McpClientErrorV1> {
    bytes
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            line.strip_prefix(b"data: ")
        })
        .ok_or(McpClientErrorV1::Protocol)
}

fn parse_depth(value: &str) -> Result<protocol::GroundingDepthV1, McpClientErrorV1> {
    match value {
        "ambient" => Ok(protocol::GroundingDepthV1::Ambient),
        "activated" => Ok(protocol::GroundingDepthV1::Activated),
        "reference" => Ok(protocol::GroundingDepthV1::Reference),
        _ => Err(McpClientErrorV1::Protocol),
    }
}

fn parse_digest(value: &str) -> Result<protocol::ContentDigestV1, McpClientErrorV1> {
    let value = value
        .strip_prefix("sha256:")
        .ok_or(McpClientErrorV1::Protocol)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(McpClientErrorV1::Protocol);
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| McpClientErrorV1::Protocol)?;
    }
    Ok(protocol::ContentDigestV1::new(digest))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceQueryV1 {
    pub load_id: String,
    pub target: String,
    pub depth: protocol::GroundingDepthV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceEntryV1 {
    pub id: Option<String>,
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceResponseV1 {
    pub version: u64,
    pub target: String,
    pub depth: protocol::GroundingDepthV1,
    pub entries: Vec<SurfaceEntryV1>,
    pub grounding_digest: protocol::ContentDigestV1,
    pub surface_digest: protocol::ContentDigestV1,
}

pub trait DendriteClient {
    type Error;

    fn query_surface(&mut self, query: &SurfaceQueryV1) -> Result<SurfaceResponseV1, Self::Error>;

    fn read_ref(&mut self, load_id: &str, target: &str) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextBindingV1 {
    Static {
        kind: protocol::ContextKindV1,
        bytes: Vec<u8>,
        source_digest: protocol::ContentDigestV1,
    },
    Dendrite {
        query: SurfaceQueryV1,
        expected_grounding_digest: protocol::ContentDigestV1,
        expected_surface_digest: protocol::ContentDigestV1,
    },
}

pub struct GroundingContextAssembler<C> {
    client: C,
    bindings: BTreeMap<protocol::ContextReferenceIdV1, ContextBindingV1>,
    messages: Vec<protocol::ModelMessageV1>,
    estimated_input_tokens: u64,
    max_context_bytes: usize,
}

impl<C> GroundingContextAssembler<C> {
    pub fn try_new(
        client: C,
        bindings: BTreeMap<protocol::ContextReferenceIdV1, ContextBindingV1>,
        messages: Vec<protocol::ModelMessageV1>,
        estimated_input_tokens: u64,
        max_context_bytes: usize,
    ) -> Option<Self> {
        if bindings.is_empty() || messages.is_empty() || max_context_bytes == 0 {
            return None;
        }
        Some(Self {
            client,
            bindings,
            messages,
            estimated_input_tokens,
            max_context_bytes,
        })
    }

    pub fn into_client(self) -> C {
        self.client
    }
}

impl<C: DendriteClient> ContextAssembler for GroundingContextAssembler<C> {
    fn assemble(
        &mut self,
        _session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
        _profile: &protocol::ProviderProfileSnapshotV1,
    ) -> Result<AssembledModelInputV1, ContextRefusalV1> {
        let requested: BTreeSet<_> = request.context.iter().copied().collect();
        if requested.len() != request.context.len()
            || request
                .context
                .iter()
                .any(|reference| !self.bindings.contains_key(reference))
        {
            return Err(ContextRefusalV1::InvalidEvidence);
        }
        let mut context = Vec::new();
        context
            .try_reserve(request.context.len())
            .map_err(|_| ContextRefusalV1::Limit)?;
        let mut total = 0usize;
        for reference in &request.context {
            let binding = self
                .bindings
                .get(reference)
                .cloned()
                .ok_or(ContextRefusalV1::InvalidEvidence)?;
            let evidence = match binding {
                ContextBindingV1::Static {
                    kind,
                    bytes,
                    source_digest,
                } => protocol::ContextEvidenceV1 {
                    reference: *reference,
                    kind,
                    bytes,
                    source_digest,
                    grounding: None,
                },
                ContextBindingV1::Dendrite {
                    query,
                    expected_grounding_digest,
                    expected_surface_digest,
                } => self.grounding(
                    *reference,
                    &query,
                    expected_grounding_digest,
                    expected_surface_digest,
                )?,
            };
            total = total
                .checked_add(evidence.bytes.len())
                .ok_or(ContextRefusalV1::Limit)?;
            if total > self.max_context_bytes || total > request.budget.max_context_bytes {
                return Err(ContextRefusalV1::Limit);
            }
            context.push(evidence);
        }
        let mut messages = self.messages.clone();
        messages
            .try_reserve(context.len())
            .map_err(|_| ContextRefusalV1::Limit)?;
        messages.extend(context.iter().map(|evidence| protocol::ModelMessageV1 {
            role: protocol::MessageRoleV1::User,
            content: evidence.bytes.clone(),
        }));
        let observed_tokens = estimated_tokens(&messages)?;
        Ok(AssembledModelInputV1 {
            context,
            messages,
            estimated_input_tokens: self.estimated_input_tokens.max(observed_tokens),
        })
    }
}

impl<C: DendriteClient> GroundingContextAssembler<C> {
    fn grounding(
        &mut self,
        reference: protocol::ContextReferenceIdV1,
        query: &SurfaceQueryV1,
        expected_grounding_digest: protocol::ContentDigestV1,
        expected_surface_digest: protocol::ContentDigestV1,
    ) -> Result<protocol::ContextEvidenceV1, ContextRefusalV1> {
        let surface = self
            .client
            .query_surface(query)
            .map_err(|_| ContextRefusalV1::Unavailable)?;
        let authority = self
            .client
            .read_ref(&query.load_id, &query.target)
            .map_err(|_| ContextRefusalV1::Unavailable)?;
        let canonical = canonical_surface(&surface)?;
        if surface.target != query.target
            || surface.depth != query.depth
            || surface.grounding_digest != expected_grounding_digest
            || surface.surface_digest != expected_surface_digest
            || sha256(&authority) != surface.grounding_digest
            || sha256(&canonical) != surface.surface_digest
        {
            return Err(ContextRefusalV1::InvalidEvidence);
        }
        Ok(protocol::ContextEvidenceV1 {
            reference,
            kind: protocol::ContextKindV1::DendriteGrounding,
            bytes: canonical,
            source_digest: surface.surface_digest,
            grounding: Some(protocol::GroundingEvidenceV1 {
                depth: surface.depth,
                grounding_digest: surface.grounding_digest,
                surface_digest: surface.surface_digest,
            }),
        })
    }
}

fn canonical_surface(surface: &SurfaceResponseV1) -> Result<Vec<u8>, ContextRefusalV1> {
    if !matches!(surface.version, 1 | 2) || surface.entries.is_empty() {
        return Err(ContextRefusalV1::InvalidEvidence);
    }
    let entries = surface
        .entries
        .iter()
        .map(|entry| match (surface.version, &entry.id) {
            (1, None) if !entry.kind.is_empty() && !entry.text.trim().is_empty() => {
                Ok(CanonicalEntry::V1 {
                    kind: &entry.kind,
                    text: &entry.text,
                })
            }
            (2, Some(id))
                if !id.is_empty() && !entry.kind.is_empty() && !entry.text.trim().is_empty() =>
            {
                Ok(CanonicalEntry::V2 {
                    id,
                    kind: &entry.kind,
                    text: &entry.text,
                })
            }
            _ => Err(ContextRefusalV1::InvalidEvidence),
        })
        .collect::<Result<Vec<_>, _>>()?;
    serde_json::to_vec(&CanonicalSurface {
        version: surface.version,
        depth: depth_name(surface.depth),
        entries,
    })
    .map_err(|_| ContextRefusalV1::InvalidEvidence)
}

#[derive(Serialize)]
struct CanonicalSurface<'a> {
    version: u64,
    depth: &'static str,
    entries: Vec<CanonicalEntry<'a>>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum CanonicalEntry<'a> {
    V1 {
        kind: &'a str,
        text: &'a str,
    },
    V2 {
        id: &'a str,
        kind: &'a str,
        text: &'a str,
    },
}

fn depth_name(depth: protocol::GroundingDepthV1) -> &'static str {
    match depth {
        protocol::GroundingDepthV1::Ambient => "ambient",
        protocol::GroundingDepthV1::Activated => "activated",
        protocol::GroundingDepthV1::Reference => "reference",
    }
}

fn sha256(bytes: &[u8]) -> protocol::ContentDigestV1 {
    protocol::ContentDigestV1::new(Sha256::digest(bytes).into())
}

fn estimated_tokens(messages: &[protocol::ModelMessageV1]) -> Result<u64, ContextRefusalV1> {
    let bytes = messages.iter().try_fold(0usize, |total, message| {
        total.checked_add(message.content.len())
    });
    u64::try_from(bytes.ok_or(ContextRefusalV1::Limit)?.div_ceil(4))
        .map_err(|_| ContextRefusalV1::Limit)
}
