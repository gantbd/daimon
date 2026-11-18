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
    ModelProvider, ModelProviderOutcomeV1,
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
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Shutdown, SocketAddr},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_QUALIFICATION_RECORDS: usize = 32;
const QUALIFICATION_PROMPT: &[u8] = b"Respond with a short confirmation that this local model can complete a bounded request. Do not request tools or propose external effects.";
static NEXT_QUALIFICATION_WRITE: AtomicU64 = AtomicU64::new(0);

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
    task_bindings: Vec<TaskBindingCatalogEntryV1<'a>>,
    contexts: Vec<ContextCatalogEntryV1<'a>>,
}

#[derive(Serialize)]
struct TaskBindingCatalogEntryV1<'a> {
    external_task_key: &'a str,
    chronos_task_id: &'a str,
}

#[derive(Serialize)]
struct ContextCatalogEntryV1<'a> {
    reference: &'a str,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<usize>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    qualification: Option<ProviderQualificationProjectionV1>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderQualificationRequestV1 {
    pub version: u8,
    pub operation_id: String,
    pub expected_document_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderQualificationProjectionV1 {
    version: u8,
    owner: String,
    operation_id: String,
    document_digest: String,
    profile_document_digest: String,
    provider_id: String,
    harness_profile_id: String,
    model: String,
    host_observed_at_unix_ms: u64,
    disposition: String,
    completion: bool,
    tool_continuation: String,
    input_tokens: u64,
    output_tokens: u64,
    output_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_digest: Option<String>,
    known_deviations: Vec<String>,
    replayed: bool,
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
    let document_digest = digest_text(Sha256::digest(&bytes).into());
    serde_json::to_string(&ProviderCatalogV1 {
        version: 1,
        owner: "daimon-local-model",
        document_digest: document_digest.clone(),
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
            qualification: latest_provider_qualification(&validated, &document_digest),
        }],
        task_bindings: validated
            .raw
            .task_bindings
            .iter()
            .map(|binding| TaskBindingCatalogEntryV1 {
                external_task_key: &binding.external_task_key,
                chronos_task_id: &binding.chronos_task_id,
            })
            .collect(),
        contexts: validated
            .raw
            .context
            .iter()
            .map(|context| ContextCatalogEntryV1 {
                reference: &context.reference,
                kind: match (context.kind, context.dendrite.as_ref()) {
                    (_, Some(_)) => "dendrite_grounding",
                    (Some(ContextKindConfigV1::AgoraMessage), None) => "agora_message",
                    (Some(ContextKindConfigV1::ChronosWork), None) => "chronos_work",
                    (Some(ContextKindConfigV1::VellumDocument), None) => "vellum_document",
                    (None, None) => "unknown",
                },
                source_digest: context
                    .text
                    .as_ref()
                    .map(|text| digest_text(Sha256::digest(text.as_bytes()).into())),
                bytes: context.text.as_ref().map(String::len),
            })
            .collect(),
    })
    .map_err(|_| ConfigErrorV1::Json)
}

/// Executes one bounded, non-retried completion-conformance request and retains
/// the redacted result under the owner store's sibling qualification directory.
/// The operation marker is committed before provider dispatch; replay returns
/// the retained receipt or an explicit outcome-unknown record and never sends a
/// second provider request.
pub fn qualify_provider_json(
    path: impl AsRef<Path>,
    request_bytes: &[u8],
) -> Result<String, ConfigErrorV1> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|_| ConfigErrorV1::Io)?;
    let raw: ConfigV1 = serde_json::from_slice(&bytes).map_err(|_| ConfigErrorV1::Json)?;
    let validated = validate(raw)?;
    let request: ProviderQualificationRequestV1 =
        serde_json::from_slice(request_bytes).map_err(|_| ConfigErrorV1::Json)?;
    let document_digest = digest_text(Sha256::digest(&bytes).into());
    if request.version != 1
        || hex_id(&request.operation_id).is_err()
        || request.expected_document_digest != document_digest
    {
        return Err(ConfigErrorV1::Invalid);
    }

    let directory = qualification_directory(&validated.raw.store_directory);
    create_private_qualification_directory(&directory)?;
    let lock_path = directory.join("owner.lock");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)
        .map_err(|_| ConfigErrorV1::Io)?;
    lock.try_lock().map_err(|_| ConfigErrorV1::Io)?;
    let record_path = directory.join(format!("{}.json", request.operation_id));
    if record_path.exists() {
        let mut retained = read_qualification(&record_path)?;
        validate_qualification_identity(&retained, &validated, &document_digest, &request)?;
        if retained.disposition == "running" {
            retained.disposition = "outcome_unknown".into();
            retained.known_deviations =
                vec!["provider_outcome_requires_operator_reconciliation".into()];
            write_qualification_atomic(&record_path, &retained)?;
        }
        retained.replayed = true;
        return serde_json::to_string(&retained).map_err(|_| ConfigErrorV1::Json);
    }
    let record_count = fs::read_dir(&directory)
        .map_err(|_| ConfigErrorV1::Io)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|value| value == "json")
        })
        .count();
    if record_count >= MAX_QUALIFICATION_RECORDS {
        return Err(ConfigErrorV1::Invalid);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConfigErrorV1::Invalid)?;
    let host_observed_at_unix_ms =
        u64::try_from(now.as_millis()).map_err(|_| ConfigErrorV1::Invalid)?;
    let mut record = qualification_record(
        &validated,
        &request,
        document_digest,
        host_observed_at_unix_ms,
    );
    write_qualification_new(&record_path, &record)?;

    let operation = hex_id(&request.operation_id)?;
    let invocation = protocol::ModelInvocationV1 {
        execution_id: protocol::ExecutionIdV1::new(operation),
        provider: validated.profile.snapshot.clone(),
        context: Vec::new(),
        messages: vec![protocol::ModelMessageV1 {
            role: protocol::MessageRoleV1::User,
            content: QUALIFICATION_PROMPT.to_vec(),
        }],
        tools: Vec::new(),
        continuation: None,
        estimated_input_tokens: u64::try_from(QUALIFICATION_PROMPT.len().div_ceil(4))
            .map_err(|_| ConfigErrorV1::Invalid)?,
    };
    let mut provider = OpenAiCompatibleProvider::try_new(std::slice::from_ref(&validated.profile))
        .ok_or(ConfigErrorV1::Invalid)?;
    match provider.execute_model(&invocation) {
        ModelProviderOutcomeV1::Receipt(receipt) => {
            record.input_tokens = receipt.input_tokens;
            record.output_tokens = receipt.output_tokens;
            record.output_bytes = receipt.output.len();
            record.evidence_digest = Some(digest_text(receipt.evidence_digest.into_bytes()));
            let completion = receipt.disposition == protocol::ExecutionDispositionV1::Completed
                && !receipt.output.is_empty()
                && receipt.input_tokens > 0
                && receipt.output_tokens > 0
                && receipt.proposals.is_empty();
            record.completion = completion;
            record.disposition = if completion {
                "qualified_completion".into()
            } else {
                "nonconformant".into()
            };
            if !completion {
                record.known_deviations.push(
                    "completion, usage, output, or no-effect-proposal invariant was not met".into(),
                );
            }
        }
        ModelProviderOutcomeV1::OutcomeUnknown => {
            record.disposition = "outcome_unknown".into();
            record
                .known_deviations
                .push("provider outcome requires operator reconciliation".into());
        }
    }
    write_qualification_atomic(&record_path, &record)?;
    serde_json::to_string(&record).map_err(|_| ConfigErrorV1::Json)
}

fn qualification_directory(store: &Path) -> PathBuf {
    let mut value = store.as_os_str().to_os_string();
    value.push(".provider-qualifications");
    PathBuf::from(value)
}

fn create_private_qualification_directory(path: &Path) -> Result<(), ConfigErrorV1> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|_| ConfigErrorV1::Io)?;
            if metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0 {
                Ok(())
            } else {
                Err(ConfigErrorV1::Invalid)
            }
        }
        Err(_) => Err(ConfigErrorV1::Io),
    }
}

fn qualification_record(
    config: &ValidatedConfigV1,
    request: &ProviderQualificationRequestV1,
    document_digest: String,
    host_observed_at_unix_ms: u64,
) -> ProviderQualificationProjectionV1 {
    ProviderQualificationProjectionV1 {
        version: 1,
        owner: "daimon-local-model".into(),
        operation_id: request.operation_id.clone(),
        document_digest,
        profile_document_digest: digest_text(config.profile.snapshot.document_digest.into_bytes()),
        provider_id: config.raw.provider.provider_id.clone(),
        harness_profile_id: config.raw.provider.harness_profile_id.clone(),
        model: config.raw.provider.model.clone(),
        host_observed_at_unix_ms,
        disposition: "running".into(),
        completion: false,
        tool_continuation: "not_exercised".into(),
        input_tokens: 0,
        output_tokens: 0,
        output_bytes: 0,
        evidence_digest: None,
        known_deviations: vec!["tool_continuation_not_exercised".into()],
        replayed: false,
    }
}

fn validate_qualification_identity(
    record: &ProviderQualificationProjectionV1,
    config: &ValidatedConfigV1,
    document_digest: &str,
    request: &ProviderQualificationRequestV1,
) -> Result<(), ConfigErrorV1> {
    if record.version == 1
        && record.owner == "daimon-local-model"
        && record.operation_id == request.operation_id
        && record.document_digest == document_digest
        && record.profile_document_digest
            == digest_text(config.profile.snapshot.document_digest.into_bytes())
        && record.provider_id == config.raw.provider.provider_id
        && record.harness_profile_id == config.raw.provider.harness_profile_id
        && record.model == config.raw.provider.model
    {
        Ok(())
    } else {
        Err(ConfigErrorV1::Invalid)
    }
}

fn write_qualification_new(
    path: &Path,
    record: &ProviderQualificationProjectionV1,
) -> Result<(), ConfigErrorV1> {
    let bytes = serde_json::to_vec(record).map_err(|_| ConfigErrorV1::Json)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ConfigErrorV1::Io)?;
    file.write_all(&bytes).map_err(|_| ConfigErrorV1::Io)?;
    file.sync_all().map_err(|_| ConfigErrorV1::Io)?;
    File::open(path.parent().ok_or(ConfigErrorV1::Invalid)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ConfigErrorV1::Io)
}

fn write_qualification_atomic(
    path: &Path,
    record: &ProviderQualificationProjectionV1,
) -> Result<(), ConfigErrorV1> {
    let temporary = path.with_extension(format!(
        "json.next-{}-{}",
        std::process::id(),
        NEXT_QUALIFICATION_WRITE.fetch_add(1, Ordering::Relaxed)
    ));
    if temporary.exists() {
        return Err(ConfigErrorV1::Invalid);
    }
    write_qualification_new(&temporary, record)?;
    fs::rename(&temporary, path).map_err(|_| ConfigErrorV1::Io)?;
    File::open(path.parent().ok_or(ConfigErrorV1::Invalid)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ConfigErrorV1::Io)
}

fn read_qualification(path: &Path) -> Result<ProviderQualificationProjectionV1, ConfigErrorV1> {
    let bytes = fs::read(path).map_err(|_| ConfigErrorV1::Io)?;
    if bytes.len() > 64 * 1024 {
        return Err(ConfigErrorV1::Invalid);
    }
    serde_json::from_slice(&bytes).map_err(|_| ConfigErrorV1::Json)
}

fn latest_provider_qualification(
    config: &ValidatedConfigV1,
    document_digest: &str,
) -> Option<ProviderQualificationProjectionV1> {
    let directory = qualification_directory(&config.raw.store_directory);
    let expected = digest_text(config.profile.snapshot.document_digest.into_bytes());
    let mut records = fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| read_qualification(&entry.path()).ok())
        .filter(|record| {
            record.version == 1
                && record.owner == "daimon-local-model"
                && hex_id(&record.operation_id).is_ok()
                && record.document_digest == document_digest
                && record.profile_document_digest == expected
                && record.provider_id == config.raw.provider.provider_id
                && record.harness_profile_id == config.raw.provider.harness_profile_id
                && record.model == config.raw.provider.model
                && matches!(
                    record.disposition.as_str(),
                    "qualified_completion" | "nonconformant" | "outcome_unknown" | "running"
                )
                && record.completion == (record.disposition == "qualified_completion")
                && record.tool_continuation == "not_exercised"
                && record.known_deviations.len() <= 8
                && record
                    .known_deviations
                    .iter()
                    .all(|deviation| !deviation.is_empty() && deviation.len() <= 256)
                && (!record.completion
                    || (record.input_tokens > 0
                        && record.output_tokens > 0
                        && record.output_bytes > 0
                        && record.evidence_digest.is_some()))
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.host_observed_at_unix_ms);
    records.pop().map(|mut record| {
        if record.disposition == "running" {
            record.disposition = "outcome_unknown".into();
            record.known_deviations =
                vec!["provider outcome requires operator reconciliation".into()];
        }
        record.replayed = false;
        record
    })
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
    run_with_shutdown(config, None)
}

/// Runs the production model service under the same explicit one-byte
/// supervisor contract as the interactive-agent owner. Only `x` requests
/// shutdown; the wake connection carries no model command and exists solely to
/// release the blocking local accept after the request is retained.
pub fn run_supervised<R>(
    config: ValidatedConfigV1,
    mut shutdown: R,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read + Send + 'static,
{
    let requested = Arc::new(AtomicBool::new(false));
    let observer = Arc::clone(&requested);
    let socket = config.raw.daimon_socket.clone();
    thread::spawn(move || {
        let mut request = [0_u8; 1];
        if shutdown.read_exact(&mut request).is_ok() && request == *b"x" {
            observer.store(true, Ordering::Release);
            let _ = UnixStream::connect(socket);
        }
    });
    run_with_shutdown(config, Some(requested))
}

fn run_with_shutdown(
    config: ValidatedConfigV1,
    shutdown: Option<Arc<AtomicBool>>,
) -> Result<(), Box<dyn std::error::Error>> {
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
        if shutdown
            .as_ref()
            .is_some_and(|requested| requested.load(Ordering::Acquire))
        {
            return Ok(());
        }
        let served = daemon.serve_next();
        if shutdown
            .as_ref()
            .is_some_and(|requested| requested.load(Ordering::Acquire))
        {
            return Ok(());
        }
        served.map_err(|_| failure("model daemon connection failed"))?;
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
