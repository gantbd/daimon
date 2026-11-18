//! Composition-only executable support for one local Daimon model profile.

#![forbid(unsafe_code)]

use aegis_client::AuthorityClient;
use chronos_client::WireClientV1;
use daimon_aegis::{AegisAuthorizer, grant_context};
use daimon_checkpoint::model::ModelStoreLimitsV1;
use daimon_chronos::{ChronosAttemptValidator, TaskBindingV1};
use daimon_dendrite::{
    ContextBindingV1, GroundingContextAssembler, McpEndpointV1, StreamableHttpClient,
    SurfaceQueryV1,
};
use daimon_host::{
    AssembledModelInputV1, AuthenticatedSessionV1, ContextAssembler, ContextRefusalV1,
};
use daimon_local_daemon::unix::{Authenticator, ModelDaemon};
use daimon_openai_local::{
    EndpointV1, LocalProfileV1, OpenAiCompatibleProvider, ResponseModeV1, StaticProfileResolver,
    profile_document_digest,
};
use daimon_protocol as protocol;
use daimon_service::{ServiceLimitsV1, model::ModelService};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigV1 {
    pub principal: String,
    pub aegis_socket: PathBuf,
    pub aegis_expected_epoch: u64,
    pub aegis_grant_now: u64,
    pub aegis_grant_expires_at: u64,
    pub chronos_socket: PathBuf,
    pub daimon_socket: PathBuf,
    pub store_directory: PathBuf,
    pub provider: ProviderConfigV1,
    pub task_bindings: Vec<TaskBindingConfigV1>,
    #[serde(default)]
    pub tool_capabilities: Vec<String>,
    #[serde(default)]
    pub context: Vec<ContextConfigV1>,
    #[serde(default)]
    pub dendrite: Option<DendriteConfigV1>,
    #[serde(default)]
    pub messages: Vec<MessageConfigV1>,
    #[serde(default = "default_io_timeout_ms")]
    pub io_timeout_ms: u64,
    #[serde(default = "default_max_executions")]
    pub max_executions: usize,
    #[serde(default = "default_max_requests")]
    pub max_requests_per_connection: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfigV1 {
    pub provider_id: String,
    pub harness_profile_id: String,
    pub model: String,
    pub address: String,
    pub host_header: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub bearer_token_env: Option<String>,
    #[serde(default)]
    pub structured_output: bool,
    #[serde(default)]
    pub structured_tools: bool,
    #[serde(default)]
    pub sampling_temperature_milli: u16,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_io_timeout_ms")]
    pub io_timeout_ms: u64,
    #[serde(default = "default_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBindingConfigV1 {
    pub external_task_key: String,
    pub chronos_task_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextConfigV1 {
    pub reference: String,
    #[serde(default)]
    pub kind: Option<ContextKindConfigV1>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub dendrite: Option<DendriteBindingConfigV1>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKindConfigV1 {
    AgoraMessage,
    ChronosWork,
    VellumDocument,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DendriteBindingConfigV1 {
    pub load_id: String,
    pub target: String,
    pub depth: GroundingDepthConfigV1,
    pub expected_grounding_digest: String,
    pub expected_surface_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundingDepthConfigV1 {
    Ambient,
    Activated,
    Reference,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DendriteConfigV1 {
    pub address: String,
    pub host_header: String,
    #[serde(default)]
    pub bearer_token_env: Option<String>,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_io_timeout_ms")]
    pub io_timeout_ms: u64,
    #[serde(default = "default_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_context_bytes")]
    pub max_context_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageConfigV1 {
    pub role: MessageRoleConfigV1,
    pub content: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRoleConfigV1 {
    System,
    User,
    Assistant,
}

#[derive(Debug)]
pub enum ConfigErrorV1 {
    Io,
    Json,
    Invalid,
    SecretUnavailable,
}

impl std::fmt::Display for ConfigErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "local model configuration: {self:?}")
    }
}

impl std::error::Error for ConfigErrorV1 {}

pub struct ValidatedConfigV1 {
    pub raw: ConfigV1,
    principal: [u8; 16],
    profile: LocalProfileV1,
    bindings: Vec<TaskBindingV1>,
    tools: Vec<[u8; 16]>,
    context: RuntimeContext,
}

#[derive(Serialize)]
struct ProviderCatalogV1<'a> {
    version: u8,
    owner: &'static str,
    document_digest: String,
    providers: [ProviderCatalogEntryV1<'a>; 1],
}

#[derive(Serialize)]
struct ProviderCatalogEntryV1<'a> {
    provider_id: &'a str,
    harness_profile_id: &'a str,
    profile_document_digest: String,
    wire: &'static str,
    model: &'a str,
    endpoint_scope: &'static str,
    endpoint_port: u16,
    structured_output: bool,
    structured_tools: bool,
    sampling_temperature_milli: u16,
    bearer_token_configured: bool,
}

/// Returns a bounded, redacted projection after validating the complete owner
/// document. Host headers, paths, credential names, and credentials are absent.
pub fn provider_catalog_json(path: impl AsRef<Path>) -> Result<String, ConfigErrorV1> {
    let bytes = fs::read(path).map_err(|_| ConfigErrorV1::Io)?;
    let raw: ConfigV1 = serde_json::from_slice(&bytes).map_err(|_| ConfigErrorV1::Json)?;
    let validated = validate(raw)?;
    let address = validated.profile.endpoint.address;
    let endpoint_scope = if address.ip().is_loopback() {
        "loopback"
    } else if match address.ip() {
        std::net::IpAddr::V4(ip) => ip.is_private(),
        std::net::IpAddr::V6(ip) => ip.is_unique_local(),
    } {
        "private_network"
    } else {
        "public_network"
    };
    serde_json::to_string(&ProviderCatalogV1 {
        version: 1,
        owner: "daimon-local-model",
        document_digest: digest_text(Sha256::digest(&bytes).into()),
        providers: [ProviderCatalogEntryV1 {
            provider_id: &validated.raw.provider.provider_id,
            harness_profile_id: &validated.raw.provider.harness_profile_id,
            profile_document_digest: digest_text(
                validated.profile.snapshot.document_digest.into_bytes(),
            ),
            wire: "openai_chat_completions",
            model: &validated.raw.provider.model,
            endpoint_scope,
            endpoint_port: address.port(),
            structured_output: validated.raw.provider.structured_output,
            structured_tools: validated.raw.provider.structured_tools,
            sampling_temperature_milli: validated.raw.provider.sampling_temperature_milli,
            bearer_token_configured: validated.raw.provider.bearer_token_env.is_some(),
        }],
    })
    .map_err(|_| ConfigErrorV1::Json)
}

fn digest_text(bytes: [u8; 32]) -> String {
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub fn load(path: impl AsRef<Path>) -> Result<ValidatedConfigV1, ConfigErrorV1> {
    let bytes = fs::read(path).map_err(|_| ConfigErrorV1::Io)?;
    let raw: ConfigV1 = serde_json::from_slice(&bytes).map_err(|_| ConfigErrorV1::Json)?;
    validate(raw)
}

pub fn validate(raw: ConfigV1) -> Result<ValidatedConfigV1, ConfigErrorV1> {
    let principal = hex_id(&raw.principal)?;
    if raw.io_timeout_ms == 0
        || raw.max_executions == 0
        || raw.max_requests_per_connection == 0
        || raw.aegis_grant_expires_at < raw.aegis_grant_now
        || raw.task_bindings.is_empty()
        || raw.messages.is_empty()
    {
        return Err(ConfigErrorV1::Invalid);
    }
    let provider_id = hex_id(&raw.provider.provider_id)?;
    let harness_profile = hex_id(&raw.provider.harness_profile_id)?;
    if raw.provider.model.is_empty() || raw.provider.model.len() > 1_024 {
        return Err(ConfigErrorV1::Invalid);
    }
    let bearer_token = secret(&raw.provider.bearer_token_env)?;
    let endpoint = EndpointV1 {
        address: SocketAddr::from_str(&raw.provider.address).map_err(|_| ConfigErrorV1::Invalid)?,
        host_header: raw.provider.host_header.clone(),
        path: raw.provider.path.clone(),
        bearer_token,
        response_mode: if raw.provider.structured_output {
            ResponseModeV1::DaimonJsonSchema
        } else {
            ResponseModeV1::PlainText
        },
        sampling_temperature_milli: raw.provider.sampling_temperature_milli,
        connect_timeout: Duration::from_millis(raw.provider.connect_timeout_ms),
        io_timeout: Duration::from_millis(raw.provider.io_timeout_ms),
        max_request_bytes: raw.provider.max_request_bytes,
        max_response_bytes: raw.provider.max_response_bytes,
    };
    let mut snapshot = protocol::ProviderProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new(provider_id),
        harness_profile: protocol::HarnessProfileIdV1::new(harness_profile),
        wire: protocol::ProviderWireProfileV1::OpenAiChatCompletions,
        model: raw.provider.model.as_bytes().to_vec(),
        structured_tools: raw.provider.structured_tools,
        document_digest: protocol::ContentDigestV1::new([0; 32]),
    };
    snapshot.document_digest = profile_document_digest(&snapshot, &endpoint);
    let profile = LocalProfileV1 { snapshot, endpoint };
    if StaticProfileResolver::try_new(std::slice::from_ref(&profile)).is_none()
        || OpenAiCompatibleProvider::try_new(std::slice::from_ref(&profile)).is_none()
    {
        return Err(ConfigErrorV1::Invalid);
    }

    let bindings = raw
        .task_bindings
        .iter()
        .map(|binding| {
            Ok(TaskBindingV1 {
                external_task_key: hex_id(&binding.external_task_key)?,
                chronos_task_id: binding.chronos_task_id.clone(),
            })
        })
        .collect::<Result<Vec<_>, ConfigErrorV1>>()?;
    let tools = raw
        .tool_capabilities
        .iter()
        .map(|value| hex_id(value))
        .collect::<Result<Vec<_>, _>>()?;
    if tools.iter().collect::<BTreeSet<_>>().len() != tools.len() {
        return Err(ConfigErrorV1::Invalid);
    }
    let context = RuntimeContext::try_new(&raw)?;
    Ok(ValidatedConfigV1 {
        raw,
        principal,
        profile,
        bindings,
        tools,
        context,
    })
}

pub fn run(config: ValidatedConfigV1) -> Result<(), Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(config.raw.io_timeout_ms);
    let (session, aegis_port) = aegis_local_daemon::unix::connect(
        &config.raw.aegis_socket,
        aegis_wire::LimitsV1::default(),
        timeout,
    )
    .map_err(|_| failure("Aegis connection failed"))?;
    let mut authority = AuthorityClient::new(session, aegis_port);
    let mut scopes = vec![aegis_protocol::ScopeV1 {
        engine: aegis_protocol::EngineNamespaceV1::Daimon,
        resource: config.profile.snapshot.harness_profile.into_bytes(),
        actions: 1 << aegis_protocol::ActionV1::Execute as u8,
    }];
    scopes.extend(config.tools.iter().map(|tool| aegis_protocol::ScopeV1 {
        engine: aegis_protocol::EngineNamespaceV1::Daimon,
        resource: *tool,
        actions: 1 << aegis_protocol::ActionV1::Execute as u8,
    }));
    let aegis_protocol::ReplyV1::Accepted(aegis_protocol::OutcomeV1::GrantIssued(grant)) =
        authority
            .issue(
                config.raw.aegis_expected_epoch,
                config.raw.aegis_grant_now,
                config.raw.aegis_grant_expires_at,
                scopes,
            )
            .map_err(|_| failure("Aegis grant issue failed"))?
    else {
        return Err(failure("Aegis grant issue refused").into());
    };
    let grant = grant.handle;
    let authorizer = AegisAuthorizer::new(authority, grant, config.principal);
    let chronos_limits = chronos_limits();
    let attempts = ChronosAttemptValidator::new(
        ChronosUnixPort {
            path: config.raw.chronos_socket.clone(),
            limits: chronos_limits,
            timeout,
        },
        chronos_limits,
        config.bindings.len(),
        config.bindings,
    )
    .map_err(|_| failure("invalid Chronos bindings"))?;
    let profiles = StaticProfileResolver::try_new(std::slice::from_ref(&config.profile))
        .ok_or_else(|| failure("invalid provider profile"))?;
    let provider = OpenAiCompatibleProvider::try_new(std::slice::from_ref(&config.profile))
        .ok_or_else(|| failure("invalid provider profile"))?;
    let store_limits = model_store_limits(config.raw.max_executions);
    let store = if config.raw.store_directory.exists() {
        daimon_local::open_existing_model(&config.raw.store_directory, store_limits)
    } else {
        daimon_local::create_new_model(&config.raw.store_directory, store_limits)
    }
    .map_err(|_| failure("model store unavailable"))?;
    let service = ModelService::open(
        daimon_harness::Limits::default(),
        ServiceLimitsV1 {
            max_sessions: 64,
            max_executions: config.raw.max_executions,
        },
        authorizer,
        attempts,
        profiles,
        config.context,
        provider,
        store,
    )
    .map_err(|_| failure("model service recovery failed"))?;
    let mut daemon = ModelDaemon::bind_new(
        &config.raw.daimon_socket,
        service,
        FixedAuthenticator {
            principal: config.principal,
            authority_context: grant_context(grant),
        },
        daimon_wire::LimitsV1::default(),
        daimon_wire::ModelLimitsV1::default(),
        timeout,
        config.raw.max_requests_per_connection,
    )?;
    loop {
        daemon
            .serve_next()
            .map_err(|_| failure("model daemon connection failed"))?;
    }
}

enum RuntimeContext {
    Static(StaticContextAssembler),
    Dendrite(GroundingContextAssembler<StreamableHttpClient>),
}

impl RuntimeContext {
    fn try_new(config: &ConfigV1) -> Result<Self, ConfigErrorV1> {
        let messages = configured_messages(&config.messages)?;
        let has_dendrite = config.context.iter().any(|item| item.dendrite.is_some());
        if has_dendrite != config.dendrite.is_some() {
            return Err(ConfigErrorV1::Invalid);
        }
        if !has_dendrite {
            return Ok(Self::Static(StaticContextAssembler::try_new(
                &config.context,
                messages,
            )?));
        }
        let dendrite = config.dendrite.as_ref().ok_or(ConfigErrorV1::Invalid)?;
        let token = secret(&dendrite.bearer_token_env)?;
        let client = StreamableHttpClient::try_new(McpEndpointV1 {
            address: dendrite
                .address
                .parse()
                .map_err(|_| ConfigErrorV1::Invalid)?,
            host_header: dendrite.host_header.clone(),
            bearer_token: token,
            connect_timeout: Duration::from_millis(dendrite.connect_timeout_ms),
            io_timeout: Duration::from_millis(dendrite.io_timeout_ms),
            max_request_bytes: dendrite.max_request_bytes,
            max_response_bytes: dendrite.max_response_bytes,
        })
        .map_err(|_| ConfigErrorV1::Invalid)?;
        let mut bindings = BTreeMap::new();
        for item in &config.context {
            let reference = protocol::ContextReferenceIdV1::new(hex_id(&item.reference)?);
            let binding = match (&item.kind, &item.text, &item.dendrite) {
                (Some(kind), Some(text), None) if !text.is_empty() => {
                    let bytes = text.as_bytes().to_vec();
                    ContextBindingV1::Static {
                        kind: context_kind(*kind),
                        source_digest: protocol::ContentDigestV1::new(
                            Sha256::digest(&bytes).into(),
                        ),
                        bytes,
                    }
                }
                (None, None, Some(binding))
                    if !binding.load_id.is_empty() && !binding.target.is_empty() =>
                {
                    ContextBindingV1::Dendrite {
                        query: SurfaceQueryV1 {
                            load_id: binding.load_id.clone(),
                            target: binding.target.clone(),
                            depth: grounding_depth(binding.depth),
                        },
                        expected_grounding_digest: digest(&binding.expected_grounding_digest)?,
                        expected_surface_digest: digest(&binding.expected_surface_digest)?,
                    }
                }
                _ => return Err(ConfigErrorV1::Invalid),
            };
            if bindings.insert(reference, binding).is_some() {
                return Err(ConfigErrorV1::Invalid);
            }
        }
        let estimated = estimate_tokens(&messages).map_err(|_| ConfigErrorV1::Invalid)?;
        let assembler = GroundingContextAssembler::try_new(
            client,
            bindings,
            messages,
            estimated,
            dendrite.max_context_bytes,
        )
        .ok_or(ConfigErrorV1::Invalid)?;
        Ok(Self::Dendrite(assembler))
    }
}

impl ContextAssembler for RuntimeContext {
    fn assemble(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
        profile: &protocol::ProviderProfileSnapshotV1,
    ) -> Result<AssembledModelInputV1, ContextRefusalV1> {
        match self {
            Self::Static(value) => value.assemble(session, request, profile),
            Self::Dendrite(value) => value.assemble(session, request, profile),
        }
    }
}

struct StaticContextAssembler {
    context: BTreeMap<protocol::ContextReferenceIdV1, protocol::ContextEvidenceV1>,
    messages: Vec<protocol::ModelMessageV1>,
}

impl StaticContextAssembler {
    fn try_new(
        context: &[ContextConfigV1],
        messages: Vec<protocol::ModelMessageV1>,
    ) -> Result<Self, ConfigErrorV1> {
        let mut by_reference = BTreeMap::new();
        for item in context {
            let reference = protocol::ContextReferenceIdV1::new(hex_id(&item.reference)?);
            let (Some(kind), Some(text), None) = (&item.kind, &item.text, &item.dendrite) else {
                return Err(ConfigErrorV1::Invalid);
            };
            let bytes = text.as_bytes().to_vec();
            if bytes.is_empty()
                || by_reference
                    .insert(
                        reference,
                        protocol::ContextEvidenceV1 {
                            reference,
                            kind: context_kind(*kind),
                            source_digest: protocol::ContentDigestV1::new(
                                Sha256::digest(&bytes).into(),
                            ),
                            bytes,
                            grounding: None,
                        },
                    )
                    .is_some()
            {
                return Err(ConfigErrorV1::Invalid);
            }
        }
        Ok(Self {
            context: by_reference,
            messages,
        })
    }
}

impl ContextAssembler for StaticContextAssembler {
    fn assemble(
        &mut self,
        _session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
        _profile: &protocol::ProviderProfileSnapshotV1,
    ) -> Result<AssembledModelInputV1, ContextRefusalV1> {
        let mut seen = BTreeSet::new();
        let mut selected = Vec::new();
        for reference in &request.context {
            if !seen.insert(*reference) {
                return Err(ContextRefusalV1::InvalidEvidence);
            }
            selected.push(
                self.context
                    .get(reference)
                    .cloned()
                    .ok_or(ContextRefusalV1::Unavailable)?,
            );
        }
        let mut messages = self.messages.clone();
        messages
            .try_reserve(selected.len())
            .map_err(|_| ContextRefusalV1::Limit)?;
        messages.extend(selected.iter().map(|item| protocol::ModelMessageV1 {
            role: protocol::MessageRoleV1::User,
            content: item.bytes.clone(),
        }));
        let estimated_input_tokens = estimate_tokens(&messages)?;
        Ok(AssembledModelInputV1 {
            context: selected,
            messages,
            estimated_input_tokens,
        })
    }
}

fn estimate_tokens(messages: &[protocol::ModelMessageV1]) -> Result<u64, ContextRefusalV1> {
    let message_bytes = messages.iter().try_fold(0usize, |total, message| {
        total.checked_add(message.content.len())
    });
    let bytes = message_bytes.ok_or(ContextRefusalV1::Limit)?;
    u64::try_from(bytes.div_ceil(4)).map_err(|_| ContextRefusalV1::Limit)
}

fn configured_messages(
    messages: &[MessageConfigV1],
) -> Result<Vec<protocol::ModelMessageV1>, ConfigErrorV1> {
    messages
        .iter()
        .map(|message| {
            if message.content.is_empty() {
                return Err(ConfigErrorV1::Invalid);
            }
            Ok(protocol::ModelMessageV1 {
                role: match message.role {
                    MessageRoleConfigV1::System => protocol::MessageRoleV1::System,
                    MessageRoleConfigV1::User => protocol::MessageRoleV1::User,
                    MessageRoleConfigV1::Assistant => protocol::MessageRoleV1::Assistant,
                },
                content: message.content.as_bytes().to_vec(),
            })
        })
        .collect()
}

fn context_kind(value: ContextKindConfigV1) -> protocol::ContextKindV1 {
    match value {
        ContextKindConfigV1::AgoraMessage => protocol::ContextKindV1::AgoraMessage,
        ContextKindConfigV1::ChronosWork => protocol::ContextKindV1::ChronosWork,
        ContextKindConfigV1::VellumDocument => protocol::ContextKindV1::VellumDocument,
    }
}

fn grounding_depth(value: GroundingDepthConfigV1) -> protocol::GroundingDepthV1 {
    match value {
        GroundingDepthConfigV1::Ambient => protocol::GroundingDepthV1::Ambient,
        GroundingDepthConfigV1::Activated => protocol::GroundingDepthV1::Activated,
        GroundingDepthConfigV1::Reference => protocol::GroundingDepthV1::Reference,
    }
}

fn digest(value: &str) -> Result<protocol::ContentDigestV1, ConfigErrorV1> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigErrorV1::Invalid);
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| ConfigErrorV1::Invalid)?;
    }
    Ok(protocol::ContentDigestV1::new(output))
}

fn secret(name: &Option<String>) -> Result<Option<Vec<u8>>, ConfigErrorV1> {
    match name {
        Some(name) if valid_env_name(name) => Ok(Some(
            std::env::var_os(name)
                .ok_or(ConfigErrorV1::SecretUnavailable)?
                .into_encoded_bytes(),
        )),
        Some(_) => Err(ConfigErrorV1::Invalid),
        None => Ok(None),
    }
}

struct FixedAuthenticator {
    principal: [u8; 16],
    authority_context: [u8; 16],
}

impl Authenticator for FixedAuthenticator {
    type Error = Infallible;

    fn authenticate(&mut self, stream: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error> {
        let _ = stream;
        Ok(AuthenticatedSessionV1 {
            principal: self.principal,
            authority_context: self.authority_context,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum ChronosPortError {
    Io,
    Wire,
}

struct ChronosUnixPort {
    path: PathBuf,
    limits: chronos_protocol::Limits,
    timeout: Duration,
}

impl WireClientV1 for ChronosUnixPort {
    type Error = ChronosPortError;

    fn request(
        &mut self,
        request: chronos_protocol::Request,
    ) -> Result<chronos_protocol::Response, Self::Error> {
        let bytes = chronos_wire::encode(&request, self.limits.max_frame_bytes)
            .map_err(|_| ChronosPortError::Wire)?;
        let mut stream = UnixStream::connect(&self.path).map_err(|_| ChronosPortError::Io)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|_| ChronosPortError::Io)?;
        stream.write_all(&bytes).map_err(|_| ChronosPortError::Io)?;
        stream.write_all(b"\n").map_err(|_| ChronosPortError::Io)?;
        stream.flush().map_err(|_| ChronosPortError::Io)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|_| ChronosPortError::Io)?;
        let mut reply = Vec::new();
        stream
            .take(
                u64::try_from(self.limits.max_frame_bytes)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut reply)
            .map_err(|_| ChronosPortError::Io)?;
        if reply.last() == Some(&b'\n') {
            reply.pop();
        }
        chronos_wire::decode_response(&reply, self.limits.max_frame_bytes)
            .map_err(|_| ChronosPortError::Wire)
    }
}

fn chronos_limits() -> chronos_protocol::Limits {
    chronos_protocol::Limits {
        max_frame_bytes: 1024 * 1024,
        max_id_bytes: 256,
        max_graph_tasks: 1024,
        max_dependencies_per_task: 128,
        max_capabilities_per_task: 64,
        max_capability_bytes: 256,
        max_page_entries: 256,
    }
}

fn model_store_limits(max_executions: usize) -> ModelStoreLimitsV1 {
    ModelStoreLimitsV1 {
        max_bytes: 32 * 1024 * 1024,
        max_executions,
        max_context_references: 256,
        max_tools: 64,
        max_model_bytes: 4 * 1024,
        max_messages: 256,
        max_message_bytes: 1024 * 1024,
        max_context_bytes: 8 * 1024 * 1024,
        max_output_bytes: 8 * 1024 * 1024,
        max_proposals: 64,
        max_proposal_bytes: 1024 * 1024,
    }
}

fn hex_id(value: &str) -> Result<[u8; 16], ConfigErrorV1> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigErrorV1::Invalid);
    }
    let mut output = [0; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| ConfigErrorV1::Invalid)?;
    }
    Ok(output)
}

fn valid_env_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn failure(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}

const fn default_io_timeout_ms() -> u64 {
    5_000
}
const fn default_connect_timeout_ms() -> u64 {
    2_000
}
const fn default_max_executions() -> usize {
    1_024
}
const fn default_max_requests() -> usize {
    64
}
const fn default_request_bytes() -> usize {
    4 * 1024 * 1024
}
const fn default_response_bytes() -> usize {
    8 * 1024 * 1024
}
const fn default_context_bytes() -> usize {
    8 * 1024 * 1024
}
fn default_path() -> String {
    "/v1/chat/completions".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ConfigV1 {
        ConfigV1 {
            principal: "01010101010101010101010101010101".into(),
            aegis_socket: "/tmp/aegis.sock".into(),
            aegis_expected_epoch: 0,
            aegis_grant_now: 1,
            aegis_grant_expires_at: 1_000,
            chronos_socket: "/tmp/chronos.sock".into(),
            daimon_socket: "/tmp/daimon-model.sock".into(),
            store_directory: "/tmp/daimon-model-store".into(),
            provider: ProviderConfigV1 {
                provider_id: "02020202020202020202020202020202".into(),
                harness_profile_id: "03030303030303030303030303030303".into(),
                model: "local-model".into(),
                address: "127.0.0.1:11434".into(),
                host_header: "127.0.0.1:11434".into(),
                path: default_path(),
                bearer_token_env: None,
                structured_output: true,
                structured_tools: false,
                sampling_temperature_milli: 0,
                connect_timeout_ms: 100,
                io_timeout_ms: 1_000,
                max_request_bytes: 65_536,
                max_response_bytes: 65_536,
            },
            task_bindings: vec![TaskBindingConfigV1 {
                external_task_key: "04040404040404040404040404040404".into(),
                chronos_task_id: "local-task".into(),
            }],
            tool_capabilities: Vec::new(),
            context: vec![ContextConfigV1 {
                reference: "05050505050505050505050505050505".into(),
                kind: Some(ContextKindConfigV1::AgoraMessage),
                text: Some("grounded question".into()),
                dendrite: None,
            }],
            dendrite: None,
            messages: vec![MessageConfigV1 {
                role: MessageRoleConfigV1::System,
                content: "answer carefully".into(),
            }],
            io_timeout_ms: 1_000,
            max_executions: 8,
            max_requests_per_connection: 4,
        }
    }

    fn request() -> protocol::ExecuteRequestV1 {
        protocol::ExecuteRequestV1 {
            execution_id: protocol::ExecutionIdV1::new([6; 16]),
            task_attempt: protocol::TaskAttemptRefV1 {
                task_key: [4; 16],
                task_incarnation: 1,
                attempt_number: 1,
            },
            principal: protocol::PrincipalIdV1::new([1; 16]),
            profile: protocol::HarnessProfileIdV1::new([3; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([7; 16]),
            context: vec![protocol::ContextReferenceIdV1::new([5; 16])],
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

    #[test]
    fn validated_profile_is_loopback_and_context_enters_exact_messages() {
        let mut validated = validate(config()).unwrap();
        assert!(validated.profile.endpoint.address.ip().is_loopback());
        assert!(!validated.profile.snapshot.structured_tools);
        let input = validated
            .context
            .assemble(
                &AuthenticatedSessionV1 {
                    principal: [1; 16],
                    authority_context: [8; 16],
                },
                &request(),
                &validated.profile.snapshot,
            )
            .unwrap();
        assert_eq!(input.context.len(), 1);
        assert_eq!(input.messages.len(), 2);
        assert_eq!(input.messages[1].content, b"grounded question");
        let expected: [u8; 32] = Sha256::digest(b"grounded question").into();
        assert_eq!(input.context[0].source_digest.into_bytes(), expected);
    }

    #[test]
    fn structured_tool_support_is_explicit_frozen_profile_policy() {
        let mut value = config();
        value.provider.structured_tools = true;
        let validated = validate(value).unwrap();
        assert!(validated.profile.snapshot.structured_tools);

        let mut drifted = validated.profile.clone();
        drifted.snapshot.structured_tools = false;
        assert!(StaticProfileResolver::try_new(&[drifted]).is_none());
    }

    #[test]
    fn non_loopback_endpoint_and_duplicate_context_are_refused() {
        let mut remote = config();
        remote.provider.address = "192.0.2.1:11434".into();
        assert!(matches!(validate(remote), Err(ConfigErrorV1::Invalid)));

        let mut duplicate = config();
        duplicate.context.push(duplicate.context[0].clone());
        assert!(matches!(validate(duplicate), Err(ConfigErrorV1::Invalid)));

        let mut invalid_sampling = config();
        invalid_sampling.provider.sampling_temperature_milli = 2_001;
        assert!(matches!(
            validate(invalid_sampling),
            Err(ConfigErrorV1::Invalid)
        ));
    }

    #[test]
    fn optional_dendrite_binding_selects_bounded_mcp_context() {
        let mut value = config();
        value.context = vec![ContextConfigV1 {
            reference: "05050505050505050505050505050505".into(),
            kind: None,
            text: None,
            dendrite: Some(DendriteBindingConfigV1 {
                load_id: "rust".into(),
                target: "rune:rust-engineering".into(),
                depth: GroundingDepthConfigV1::Activated,
                expected_grounding_digest: "11".repeat(32),
                expected_surface_digest: "22".repeat(32),
            }),
        }];
        value.dendrite = Some(DendriteConfigV1 {
            address: "127.0.0.1:4499".into(),
            host_header: "127.0.0.1:4499".into(),
            bearer_token_env: None,
            connect_timeout_ms: 100,
            io_timeout_ms: 1_000,
            max_request_bytes: 65_536,
            max_response_bytes: 65_536,
            max_context_bytes: 65_536,
        });
        assert!(matches!(
            validate(value).unwrap().context,
            RuntimeContext::Dendrite(_)
        ));
    }

    #[test]
    fn unknown_fields_are_refused_by_json_contract() {
        let json = serde_json::json!({
            "principal": "01010101010101010101010101010101",
            "aegis_socket": "/tmp/aegis.sock",
            "aegis_expected_epoch": 0,
            "aegis_grant_now": 1,
            "aegis_grant_expires_at": 10,
            "chronos_socket": "/tmp/chronos.sock",
            "daimon_socket": "/tmp/daimon.sock",
            "store_directory": "/tmp/store",
            "provider": {
                "provider_id": "02020202020202020202020202020202",
                "harness_profile_id": "03030303030303030303030303030303",
                "model": "model",
                "address": "127.0.0.1:1",
                "host_header": "localhost",
                "surprise": true
            },
            "task_bindings": [],
            "messages": []
        });
        assert!(serde_json::from_value::<ConfigV1>(json).is_err());
    }
}
