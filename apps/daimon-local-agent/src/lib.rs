//! Production composition root for the local interactive-agent daemon.

#![forbid(unsafe_code)]

use aegis_client::AuthorityClient;
use chronos_client::WireClientV1;
use daimon_acp::{AcpLaunchProfileV1, AcpLimitsV1, AcpProvider, AcpWorkspaceV1};
use daimon_aegis::{AegisAuthorizer, grant_context};
use daimon_agent_router::{AgentProviderRouteV1, AgentProviderRouter, StaticAgentProfileRouter};
use daimon_checkpoint::agent::AgentStoreLimitsV1;
use daimon_chronos::{ChronosAttemptValidator, TaskBindingV1};
use daimon_claude::{ClaudeLaunchProfileV1, ClaudeLimitsV1, ClaudeProvider, ClaudeWorkspaceV1};
use daimon_host::{
    AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1, AuthorityGrantV1,
    AuthorityRefusalV1, ContextRefusalV1, ExecutionAuthorizer,
    agent::{
        AgentClientFileReader, AgentClientTerminal, AgentContextAssembler, AgentFileReadReceiptV1,
        AgentFileReadRefusalV1, AgentFileReadRequestV1, AgentTerminalCreateRequestV1,
        AgentTerminalCreatedV1, AgentTerminalExitV1, AgentTerminalOutputV1, AgentTerminalRefusalV1,
    },
};
use daimon_local_daemon::unix::{AgentDaemon, Authenticator};
use daimon_process::{
    ProcessBoundaryExitV1, ProcessBoundaryLaunchV1, ProcessBoundaryV1, ProcessIsolationV1,
};
use daimon_protocol::{self as protocol, agent::*};
use daimon_service::agent::{AgentService, AgentServiceLimitsV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Component, Path, PathBuf},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use vellum_adapter_local_authentication::{LocalCredentialClaimProviderV1, LocalCredentialStoreV1};
use vellum_sdk_client::{
    protocol::{SnapshotV1, WorkspaceDocumentIdV1, WorkspaceIdV1},
    transport::{AuthenticatedUnixConnector, RemoteTransport, TransportLimits},
    workspace::WorkspaceClientV1,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    pub providers: Vec<ProviderConfigV1>,
    pub workspaces: Vec<WorkspaceConfigV1>,
    pub task_bindings: Vec<TaskBindingConfigV1>,
    #[serde(default)]
    pub tool_capabilities: Vec<String>,
    #[serde(default)]
    pub context: Vec<ContextConfigV1>,
    #[serde(default)]
    pub vellum_context: Vec<VellumContextConfigV1>,
    #[serde(default = "default_io_timeout_ms")]
    pub io_timeout_ms: u64,
    #[serde(default = "default_max_agent_sessions")]
    pub max_agent_sessions: usize,
    #[serde(default = "default_max_service_sessions")]
    pub max_service_sessions: usize,
    #[serde(default = "default_max_requests")]
    pub max_requests_per_connection: usize,
    #[serde(default = "default_max_store_bytes")]
    pub max_store_bytes: usize,
    #[serde(default = "default_max_context_bytes")]
    pub max_context_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfigV1 {
    pub provider_id: String,
    pub harness_profile_id: String,
    pub policy_digest: String,
    pub program: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub inherited_environment_names: Vec<String>,
    #[serde(default)]
    pub acp_agent_authentication_method: Option<String>,
    #[serde(default)]
    pub isolation: IsolationConfigV1,
    pub transport: TransportConfigV1,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IsolationConfigV1 {
    #[default]
    Direct,
    MacosSeatbelt {
        policy_path: PathBuf,
        policy_digest: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportConfigV1 {
    Acp,
    ClaudeStreamJson,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfigV1 {
    pub identity: String,
    pub path: PathBuf,
    #[serde(default)]
    pub acp_file_read: Option<AcpFileReadConfigV1>,
    #[serde(default)]
    pub acp_terminal: Option<AcpTerminalConfigV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpFileReadConfigV1 {
    /// Daimon tool capability required in both open and callback executions.
    pub capability: String,
    /// Workspace-relative files or directories. Symlinks are resolved before
    /// containment is accepted; an empty list is invalid.
    pub paths: Vec<PathBuf>,
    #[serde(default = "default_max_file_read_bytes")]
    pub max_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpTerminalConfigV1 {
    pub capability: String,
    /// Absolute path to the separately built `daimon-process-boundary`.
    pub boundary_program: PathBuf,
    /// Exact command names mapped to absolute executables and approved argument
    /// prefixes. No PATH lookup or shell interpolation occurs at callback time.
    pub commands: Vec<AcpTerminalCommandConfigV1>,
    #[serde(default)]
    pub environment_names: Vec<String>,
    #[serde(default = "default_max_terminal_handles")]
    pub max_handles: usize,
    #[serde(default = "default_max_terminal_output_bytes")]
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpTerminalCommandConfigV1 {
    pub command: String,
    pub program: PathBuf,
    #[serde(default)]
    pub argument_prefix: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBindingConfigV1 {
    pub external_task_key: String,
    pub chronos_task_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextConfigV1 {
    pub reference: String,
    pub kind: ContextKindConfigV1,
    pub text: String,
    #[serde(default)]
    pub grounding: Option<GroundingConfigV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VellumContextConfigV1 {
    pub reference: String,
    pub socket: PathBuf,
    pub credential: PathBuf,
    pub workspace_id: u64,
    pub document_ordinal: u64,
    pub expected_revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKindConfigV1 {
    AgoraMessage,
    ChronosWork,
    VellumDocument,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundingConfigV1 {
    pub depth: GroundingDepthConfigV1,
    pub grounding_digest: String,
    pub surface_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundingDepthConfigV1 {
    Ambient,
    Activated,
    Reference,
}

#[derive(Debug)]
pub enum ConfigErrorV1 {
    Io,
    Json,
    Invalid,
}

impl std::fmt::Display for ConfigErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "local agent configuration: {self:?}")
    }
}

impl std::error::Error for ConfigErrorV1 {}

pub struct ValidatedConfigV1 {
    pub raw: ConfigV1,
    principal: [u8; 16],
    profiles: Vec<AgentProfileSnapshotV1>,
    bindings: Vec<TaskBindingV1>,
    tools: Vec<[u8; 16]>,
    context: AgentContext,
    file_read_scopes: Vec<AgentFileReadScopeV1>,
    terminal_scopes: Vec<AgentTerminalScopeV1>,
}

#[derive(Serialize)]
struct ProviderCatalogV1<'a> {
    version: u8,
    owner: &'static str,
    document_digest: String,
    providers: Vec<ProviderCatalogEntryV1<'a>>,
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
    resolution: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    document_ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_revision: Option<u64>,
}

#[derive(Serialize)]
struct ProviderCatalogEntryV1<'a> {
    provider_id: &'a str,
    harness_profile_id: &'a str,
    policy_digest: &'a str,
    profile_document_digest: String,
    transport: &'static str,
    isolation: &'static str,
    executable_available: bool,
    argument_count: usize,
    inherited_environment_name_count: usize,
    authentication_method_configured: bool,
}

/// Returns a bounded, redacted projection after validating the complete owner
/// document. Commands, arguments, paths, environment names, and credentials are
/// deliberately absent.
pub fn provider_catalog_json(path: impl AsRef<Path>) -> Result<String, ConfigErrorV1> {
    let bytes = fs::read(path).map_err(|_| ConfigErrorV1::Io)?;
    let raw: ConfigV1 = serde_json::from_slice(&bytes).map_err(|_| ConfigErrorV1::Json)?;
    let validated = validate(raw)?;
    let providers = validated
        .raw
        .providers
        .iter()
        .zip(validated.profiles.iter())
        .map(|(provider, profile)| ProviderCatalogEntryV1 {
            provider_id: &provider.provider_id,
            harness_profile_id: &provider.harness_profile_id,
            policy_digest: &provider.policy_digest,
            profile_document_digest: digest_text(profile.document_digest.into_bytes()),
            transport: match provider.transport {
                TransportConfigV1::Acp => "acp",
                TransportConfigV1::ClaudeStreamJson => "claude_stream_json",
            },
            isolation: match provider.isolation {
                IsolationConfigV1::Direct => "direct",
                IsolationConfigV1::MacosSeatbelt { .. } => "macos_seatbelt",
            },
            executable_available: true,
            argument_count: provider.arguments.len(),
            inherited_environment_name_count: provider.inherited_environment_names.len(),
            authentication_method_configured: provider.acp_agent_authentication_method.is_some(),
        })
        .collect();
    let task_bindings = validated
        .raw
        .task_bindings
        .iter()
        .map(|binding| TaskBindingCatalogEntryV1 {
            external_task_key: &binding.external_task_key,
            chronos_task_id: &binding.chronos_task_id,
        })
        .collect();
    let contexts = validated
        .raw
        .context
        .iter()
        .map(|context| ContextCatalogEntryV1 {
            reference: &context.reference,
            kind: match context.kind {
                ContextKindConfigV1::AgoraMessage => "agora_message",
                ContextKindConfigV1::ChronosWork => "chronos_work",
                ContextKindConfigV1::VellumDocument => "vellum_document",
            },
            resolution: "static_owner_document",
            source_digest: Some(digest_text(Sha256::digest(context.text.as_bytes()).into())),
            bytes: Some(context.text.len()),
            workspace_id: None,
            document_ordinal: None,
            expected_revision: None,
        })
        .chain(
            validated
                .raw
                .vellum_context
                .iter()
                .map(|context| ContextCatalogEntryV1 {
                    reference: &context.reference,
                    kind: "vellum_document",
                    resolution: "runtime_owner",
                    source_digest: None,
                    bytes: None,
                    workspace_id: Some(context.workspace_id),
                    document_ordinal: Some(context.document_ordinal),
                    expected_revision: Some(context.expected_revision),
                }),
        )
        .collect();
    serde_json::to_string(&ProviderCatalogV1 {
        version: 1,
        owner: "daimon-local-agent",
        document_digest: digest_text(Sha256::digest(&bytes).into()),
        providers,
        task_bindings,
        contexts,
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

const MAX_OWNER_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum ProviderEditErrorV1 {
    Io,
    Json,
    Invalid,
    Conflict,
    PlanMismatch,
    Busy,
    NoChange,
}

impl std::fmt::Display for ProviderEditErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let orientation = match self {
            Self::Io => "owner document could not be read or replaced",
            Self::Json => "request or owner document is not valid JSON",
            Self::Invalid => "request or candidate owner document is invalid",
            Self::Conflict => "owner document changed; refresh and review a new plan",
            Self::PlanMismatch => "confirmation does not match the reviewed plan",
            Self::Busy => "another provider edit is in progress; try again after it completes",
            Self::NoChange => {
                "provider already matches the requested configuration; no apply is needed"
            }
        };
        write!(formatter, "provider edit: {orientation}")
    }
}

impl std::error::Error for ProviderEditErrorV1 {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEditPlanRequestV1 {
    version: u8,
    operation_id: String,
    expected_document_digest: String,
    provider: ProviderConfigV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEditApplyRequestV1 {
    version: u8,
    operation_id: String,
    expected_document_digest: String,
    expected_plan_digest: String,
    expected_candidate_document_digest: String,
    provider: ProviderConfigV1,
}

#[derive(Serialize)]
struct ProviderEditPlanV1 {
    version: u8,
    owner: &'static str,
    operation_id: String,
    action: &'static str,
    expected_document_digest: String,
    current_document_digest: String,
    candidate_document_digest: String,
    plan_digest: String,
    provider: ProviderEditProjectionV1,
    changed_fields: Vec<&'static str>,
    restart_required: bool,
}

#[derive(Serialize)]
struct ProviderEditProjectionV1 {
    provider_id: String,
    harness_profile_id: String,
    policy_digest: String,
    profile_document_digest: String,
    transport: &'static str,
    isolation: &'static str,
    executable_available: bool,
    argument_count: usize,
    inherited_environment_name_count: usize,
    authentication_method_configured: bool,
}

#[derive(Serialize)]
struct ProviderEditReceiptV1 {
    version: u8,
    owner: &'static str,
    operation_id: String,
    disposition: &'static str,
    applied: bool,
    replayed: bool,
    document_digest: String,
    provider_id: String,
    restart_required: bool,
}

/// Produces the exact, redacted change plan which must be confirmed before an
/// owner document can be replaced. Launch material never appears in the plan.
pub fn plan_provider_edit_json(
    path: impl AsRef<Path>,
    request: &[u8],
) -> Result<String, ProviderEditErrorV1> {
    let request: ProviderEditPlanRequestV1 =
        serde_json::from_slice(request).map_err(|_| ProviderEditErrorV1::Json)?;
    validate_edit_header(
        request.version,
        &request.operation_id,
        &request.expected_document_digest,
    )?;
    let path = path.as_ref();
    let (bytes, current) = read_owner_document(path)?;
    let current_digest = digest_text(Sha256::digest(&bytes).into());
    if current_digest != request.expected_document_digest {
        return Err(ProviderEditErrorV1::Conflict);
    }
    let existing = current
        .providers
        .iter()
        .find(|provider| provider.provider_id == request.provider.provider_id)
        .cloned();
    if existing.as_ref() == Some(&request.provider) {
        return Err(ProviderEditErrorV1::NoChange);
    }
    let (candidate, candidate_bytes) = candidate_document(current, request.provider.clone())?;
    let candidate_digest = digest_text(Sha256::digest(&candidate_bytes).into());
    let plan_digest =
        provider_edit_plan_digest(&request.operation_id, &current_digest, &candidate_digest);
    let provider = candidate
        .providers
        .iter()
        .find(|provider| provider.provider_id == request.provider.provider_id)
        .ok_or(ProviderEditErrorV1::Invalid)?;
    let profile = validate(candidate.clone())
        .map_err(map_config_edit_error)?
        .profiles
        .into_iter()
        .zip(candidate.providers.iter())
        .find(|(_, configured)| configured.provider_id == provider.provider_id)
        .map(|(profile, _)| profile)
        .ok_or(ProviderEditErrorV1::Invalid)?;
    serde_json::to_string(&ProviderEditPlanV1 {
        version: 1,
        owner: "daimon-local-agent",
        operation_id: request.operation_id,
        action: if existing.is_some() { "replace" } else { "add" },
        expected_document_digest: request.expected_document_digest,
        current_document_digest: current_digest,
        candidate_document_digest: candidate_digest,
        plan_digest,
        provider: provider_edit_projection(provider, profile.document_digest.into_bytes()),
        changed_fields: changed_provider_fields(existing.as_ref(), provider),
        restart_required: true,
    })
    .map_err(|_| ProviderEditErrorV1::Json)
}

/// Applies only the byte-exact candidate previously planned by this owner.
/// Replaying the same confirmed operation is successful without rewriting.
pub fn apply_provider_edit_json(
    path: impl AsRef<Path>,
    request: &[u8],
) -> Result<String, ProviderEditErrorV1> {
    let request: ProviderEditApplyRequestV1 =
        serde_json::from_slice(request).map_err(|_| ProviderEditErrorV1::Json)?;
    validate_edit_header(
        request.version,
        &request.operation_id,
        &request.expected_document_digest,
    )?;
    validate_digest(&request.expected_plan_digest)?;
    validate_digest(&request.expected_candidate_document_digest)?;
    let calculated_plan = provider_edit_plan_digest(
        &request.operation_id,
        &request.expected_document_digest,
        &request.expected_candidate_document_digest,
    );
    if calculated_plan != request.expected_plan_digest {
        return Err(ProviderEditErrorV1::PlanMismatch);
    }

    let path = path.as_ref();
    let _lock = EditLockV1::acquire(path, &request.operation_id)?;
    let (bytes, current) = read_owner_document(path)?;
    let current_digest = digest_text(Sha256::digest(&bytes).into());
    if current_digest == request.expected_candidate_document_digest {
        let provider_matches = current
            .providers
            .iter()
            .any(|provider| provider == &request.provider);
        if !provider_matches {
            return Err(ProviderEditErrorV1::PlanMismatch);
        }
        return provider_edit_receipt(&request, true);
    }
    if current_digest != request.expected_document_digest {
        return Err(ProviderEditErrorV1::Conflict);
    }
    let (_, candidate_bytes) = candidate_document(current, request.provider.clone())?;
    let candidate_digest = digest_text(Sha256::digest(&candidate_bytes).into());
    if candidate_digest != request.expected_candidate_document_digest {
        return Err(ProviderEditErrorV1::PlanMismatch);
    }
    atomic_replace_owner_document(path, &request.operation_id, &candidate_bytes)?;
    provider_edit_receipt(&request, false)
}

fn provider_edit_receipt(
    request: &ProviderEditApplyRequestV1,
    replayed: bool,
) -> Result<String, ProviderEditErrorV1> {
    serde_json::to_string(&ProviderEditReceiptV1 {
        version: 1,
        owner: "daimon-local-agent",
        operation_id: request.operation_id.clone(),
        disposition: if replayed {
            "already_applied"
        } else {
            "applied"
        },
        applied: true,
        replayed,
        document_digest: request.expected_candidate_document_digest.clone(),
        provider_id: request.provider.provider_id.clone(),
        restart_required: true,
    })
    .map_err(|_| ProviderEditErrorV1::Json)
}

fn validate_edit_header(
    version: u8,
    operation_id: &str,
    document_digest: &str,
) -> Result<(), ProviderEditErrorV1> {
    if version != 1
        || operation_id.len() != 32
        || !operation_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProviderEditErrorV1::Invalid);
    }
    validate_digest(document_digest)
}

fn validate_digest(digest: &str) -> Result<(), ProviderEditErrorV1> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(ProviderEditErrorV1::Invalid);
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProviderEditErrorV1::Invalid);
    }
    Ok(())
}

fn read_owner_document(path: &Path) -> Result<(Vec<u8>, ConfigV1), ProviderEditErrorV1> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProviderEditErrorV1::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_OWNER_DOCUMENT_BYTES
    {
        return Err(ProviderEditErrorV1::Invalid);
    }
    let bytes = fs::read(path).map_err(|_| ProviderEditErrorV1::Io)?;
    let raw: ConfigV1 = serde_json::from_slice(&bytes).map_err(|_| ProviderEditErrorV1::Json)?;
    validate(raw.clone()).map_err(map_config_edit_error)?;
    Ok((bytes, raw))
}

fn candidate_document(
    mut current: ConfigV1,
    provider: ProviderConfigV1,
) -> Result<(ConfigV1, Vec<u8>), ProviderEditErrorV1> {
    if let Some(existing) = current
        .providers
        .iter_mut()
        .find(|existing| existing.provider_id == provider.provider_id)
    {
        *existing = provider;
    } else {
        current.providers.push(provider);
    }
    validate(current.clone()).map_err(map_config_edit_error)?;
    let mut bytes = serde_json::to_vec_pretty(&current).map_err(|_| ProviderEditErrorV1::Json)?;
    bytes.push(b'\n');
    Ok((current, bytes))
}

fn provider_edit_plan_digest(operation_id: &str, current: &str, candidate: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [
        b"daimon-local-agent/provider-edit/v1".as_slice(),
        operation_id.as_bytes(),
        current.as_bytes(),
        candidate.as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    digest_text(hasher.finalize().into())
}

fn changed_provider_fields(
    existing: Option<&ProviderConfigV1>,
    candidate: &ProviderConfigV1,
) -> Vec<&'static str> {
    let Some(existing) = existing else {
        return vec!["provider_added"];
    };
    let mut fields = Vec::new();
    if existing.harness_profile_id != candidate.harness_profile_id {
        fields.push("harness_profile_id");
    }
    if existing.policy_digest != candidate.policy_digest {
        fields.push("policy_digest");
    }
    if existing.program != candidate.program {
        fields.push("program");
    }
    if existing.arguments != candidate.arguments {
        fields.push("arguments");
    }
    if existing.inherited_environment_names != candidate.inherited_environment_names {
        fields.push("inherited_environment_names");
    }
    if existing.acp_agent_authentication_method != candidate.acp_agent_authentication_method {
        fields.push("authentication_method");
    }
    if existing.isolation != candidate.isolation {
        fields.push("isolation");
    }
    if existing.transport != candidate.transport {
        fields.push("transport");
    }
    fields
}

fn provider_edit_projection(
    provider: &ProviderConfigV1,
    profile_document_digest: [u8; 32],
) -> ProviderEditProjectionV1 {
    ProviderEditProjectionV1 {
        provider_id: provider.provider_id.clone(),
        harness_profile_id: provider.harness_profile_id.clone(),
        policy_digest: provider.policy_digest.clone(),
        profile_document_digest: digest_text(profile_document_digest),
        transport: match provider.transport {
            TransportConfigV1::Acp => "acp",
            TransportConfigV1::ClaudeStreamJson => "claude_stream_json",
        },
        isolation: match provider.isolation {
            IsolationConfigV1::Direct => "direct",
            IsolationConfigV1::MacosSeatbelt { .. } => "macos_seatbelt",
        },
        executable_available: provider.program.is_file(),
        argument_count: provider.arguments.len(),
        inherited_environment_name_count: provider.inherited_environment_names.len(),
        authentication_method_configured: provider.acp_agent_authentication_method.is_some(),
    }
}

fn map_config_edit_error(error: ConfigErrorV1) -> ProviderEditErrorV1 {
    match error {
        ConfigErrorV1::Io => ProviderEditErrorV1::Io,
        ConfigErrorV1::Json => ProviderEditErrorV1::Json,
        ConfigErrorV1::Invalid => ProviderEditErrorV1::Invalid,
    }
}

struct EditLockV1 {
    path: PathBuf,
}

impl EditLockV1 {
    fn acquire(path: &Path, operation_id: &str) -> Result<Self, ProviderEditErrorV1> {
        let lock_path = sibling_path(path, ".provider-edit.lock")?;
        let mut lock = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
        {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ProviderEditErrorV1::Busy);
            }
            Err(_) => return Err(ProviderEditErrorV1::Io),
        };
        if lock.write_all(operation_id.as_bytes()).is_err() || lock.sync_all().is_err() {
            let _ = fs::remove_file(&lock_path);
            return Err(ProviderEditErrorV1::Io);
        }
        Ok(Self { path: lock_path })
    }
}

impl Drop for EditLockV1 {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf, ProviderEditErrorV1> {
    let name = path.file_name().ok_or(ProviderEditErrorV1::Invalid)?;
    let mut sibling = OsString::from(name);
    sibling.push(suffix);
    Ok(path.with_file_name(sibling))
}

fn atomic_replace_owner_document(
    path: &Path,
    operation_id: &str,
    bytes: &[u8],
) -> Result<(), ProviderEditErrorV1> {
    let temporary_path = sibling_path(path, &format!(".provider-edit-{operation_id}.tmp"))?;
    let permissions = fs::metadata(path)
        .map_err(|_| ProviderEditErrorV1::Io)?
        .permissions()
        .mode();
    let result = (|| {
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(permissions)
            .open(&temporary_path)
            .map_err(|_| ProviderEditErrorV1::Io)?;
        temporary
            .write_all(bytes)
            .map_err(|_| ProviderEditErrorV1::Io)?;
        temporary.sync_all().map_err(|_| ProviderEditErrorV1::Io)?;
        fs::set_permissions(&temporary_path, fs::Permissions::from_mode(permissions))
            .map_err(|_| ProviderEditErrorV1::Io)?;
        fs::rename(&temporary_path, path).map_err(|_| ProviderEditErrorV1::Io)?;
        let parent = path.parent().ok_or(ProviderEditErrorV1::Invalid)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProviderEditErrorV1::Io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[derive(Clone)]
struct AgentFileReadScopeV1 {
    workspace: [u8; 16],
    workspace_path: PathBuf,
    capability: protocol::ToolCapabilityIdV1,
    paths: Vec<AgentFileReadRootV1>,
    max_bytes: usize,
}

#[derive(Clone)]
struct AgentFileReadRootV1 {
    path: PathBuf,
    directory: bool,
}

#[derive(Clone)]
struct AgentTerminalScopeV1 {
    workspace: [u8; 16],
    workspace_path: PathBuf,
    capability: protocol::ToolCapabilityIdV1,
    boundary_program: PathBuf,
    commands: BTreeMap<String, AgentTerminalCommandV1>,
    environment_names: BTreeSet<String>,
    max_handles: usize,
    max_output_bytes: usize,
}

#[derive(Clone)]
struct AgentTerminalCommandV1 {
    program: PathBuf,
    argument_prefix: Vec<String>,
}

pub fn load(path: impl AsRef<Path>) -> Result<ValidatedConfigV1, ConfigErrorV1> {
    let bytes = fs::read(path).map_err(|_| ConfigErrorV1::Io)?;
    let raw = serde_json::from_slice(&bytes).map_err(|_| ConfigErrorV1::Json)?;
    validate(raw)
}

pub fn validate(raw: ConfigV1) -> Result<ValidatedConfigV1, ConfigErrorV1> {
    let principal = hex_id(&raw.principal)?;
    if raw.io_timeout_ms == 0
        || raw.max_agent_sessions == 0
        || raw.max_service_sessions == 0
        || raw.max_requests_per_connection == 0
        || raw.max_store_bytes == 0
        || raw.max_context_bytes == 0
        || raw.aegis_grant_expires_at < raw.aegis_grant_now
        || raw.providers.is_empty()
        || raw.workspaces.is_empty()
        || raw.task_bindings.is_empty()
        || !raw.aegis_socket.is_absolute()
        || !raw.chronos_socket.is_absolute()
        || !raw.daimon_socket.is_absolute()
        || !raw.store_directory.is_absolute()
        || raw.aegis_socket == raw.chronos_socket
        || raw.aegis_socket == raw.daimon_socket
        || raw.chronos_socket == raw.daimon_socket
    {
        return Err(ConfigErrorV1::Invalid);
    }

    let profiles = raw
        .providers
        .iter()
        .map(profile_snapshot)
        .collect::<Result<Vec<_>, _>>()?;
    StaticAgentProfileRouter::try_new(raw.providers.len(), profiles.clone())
        .map_err(|_| ConfigErrorV1::Invalid)?;
    // Constructors perform the adapter-specific closed configuration checks;
    // no process is started and no peer or store is opened here.
    build_provider_router(&raw, &profiles, None, None)?;

    let bindings = raw
        .task_bindings
        .iter()
        .map(|binding| {
            if binding.chronos_task_id.is_empty() || binding.chronos_task_id.len() > 256 {
                return Err(ConfigErrorV1::Invalid);
            }
            Ok(TaskBindingV1 {
                external_task_key: hex_id(&binding.external_task_key)?,
                chronos_task_id: binding.chronos_task_id.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tools = raw
        .tool_capabilities
        .iter()
        .map(|value| hex_id(value))
        .collect::<Result<Vec<_>, _>>()?;
    if tools.iter().collect::<BTreeSet<_>>().len() != tools.len() {
        return Err(ConfigErrorV1::Invalid);
    }
    let file_read_scopes = validate_file_read_scopes(&raw.workspaces, &tools)?;
    let terminal_scopes = validate_terminal_scopes(&raw.workspaces, &tools)?;
    let context = AgentContext::try_new(
        &raw.context,
        &raw.vellum_context,
        raw.max_context_bytes,
        Duration::from_millis(raw.io_timeout_ms),
    )?;
    Ok(ValidatedConfigV1 {
        raw,
        principal,
        profiles,
        bindings,
        tools,
        context,
        file_read_scopes,
        terminal_scopes,
    })
}

fn validate_file_read_scopes(
    workspaces: &[WorkspaceConfigV1],
    tools: &[[u8; 16]],
) -> Result<Vec<AgentFileReadScopeV1>, ConfigErrorV1> {
    let mut scopes = Vec::new();
    for workspace in workspaces {
        let Some(config) = &workspace.acp_file_read else {
            continue;
        };
        if config.paths.is_empty()
            || config.max_bytes == 0
            || config.max_bytes > AcpLimitsV1::default().max_event_bytes
        {
            return Err(ConfigErrorV1::Invalid);
        }
        let workspace_id = hex_id(&workspace.identity)?;
        let capability = hex_id(&config.capability)?;
        if !tools.contains(&capability) {
            return Err(ConfigErrorV1::Invalid);
        }
        let workspace_path = fs::canonicalize(&workspace.path).map_err(|_| ConfigErrorV1::Io)?;
        if !workspace_path.is_dir() {
            return Err(ConfigErrorV1::Invalid);
        }
        let mut paths = Vec::new();
        for configured in &config.paths {
            if !valid_relative_scope(configured) {
                return Err(ConfigErrorV1::Invalid);
            }
            let canonical =
                fs::canonicalize(workspace_path.join(configured)).map_err(|_| ConfigErrorV1::Io)?;
            let directory = canonical.is_dir();
            if !canonical.starts_with(&workspace_path)
                || (!directory && !canonical.is_file())
                || paths
                    .iter()
                    .any(|root: &AgentFileReadRootV1| root.path == canonical)
            {
                return Err(ConfigErrorV1::Invalid);
            }
            paths.push(AgentFileReadRootV1 {
                path: canonical,
                directory,
            });
        }
        scopes.push(AgentFileReadScopeV1 {
            workspace: workspace_id,
            workspace_path,
            capability: protocol::ToolCapabilityIdV1::new(capability),
            paths,
            max_bytes: config.max_bytes,
        });
    }
    Ok(scopes)
}

fn validate_terminal_scopes(
    workspaces: &[WorkspaceConfigV1],
    tools: &[[u8; 16]],
) -> Result<Vec<AgentTerminalScopeV1>, ConfigErrorV1> {
    let mut scopes = Vec::new();
    for workspace in workspaces {
        let Some(config) = &workspace.acp_terminal else {
            continue;
        };
        if config.commands.is_empty()
            || !(1..=8).contains(&config.max_handles)
            || config.max_output_bytes > daimon_process::MAX_TERMINAL_OUTPUT_BYTES
            || !config.boundary_program.is_absolute()
            || !config.boundary_program.is_file()
            || config.environment_names.len() > 64
            || config
                .environment_names
                .iter()
                .any(|name| !valid_env_name(name))
            || config
                .environment_names
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != config.environment_names.len()
        {
            return Err(ConfigErrorV1::Invalid);
        }
        let workspace_id = hex_id(&workspace.identity)?;
        let capability = hex_id(&config.capability)?;
        if !tools.contains(&capability) {
            return Err(ConfigErrorV1::Invalid);
        }
        let workspace_path = fs::canonicalize(&workspace.path).map_err(|_| ConfigErrorV1::Io)?;
        let boundary_program =
            fs::canonicalize(&config.boundary_program).map_err(|_| ConfigErrorV1::Io)?;
        if !workspace_path.is_dir() || !boundary_program.is_file() {
            return Err(ConfigErrorV1::Invalid);
        }
        let mut commands = BTreeMap::new();
        for command in &config.commands {
            if command.command.is_empty()
                || command.command.len() > 4096
                || command.command.contains('\0')
                || !command.program.is_absolute()
                || command.argument_prefix.len() > 255
                || command.argument_prefix.iter().any(|argument| {
                    argument.is_empty() || argument.len() > 4096 || argument.contains('\0')
                })
            {
                return Err(ConfigErrorV1::Invalid);
            }
            let program = fs::canonicalize(&command.program).map_err(|_| ConfigErrorV1::Io)?;
            if !program.is_file()
                || commands
                    .insert(
                        command.command.clone(),
                        AgentTerminalCommandV1 {
                            program,
                            argument_prefix: command.argument_prefix.clone(),
                        },
                    )
                    .is_some()
            {
                return Err(ConfigErrorV1::Invalid);
            }
        }
        scopes.push(AgentTerminalScopeV1 {
            workspace: workspace_id,
            workspace_path,
            capability: protocol::ToolCapabilityIdV1::new(capability),
            boundary_program,
            commands,
            environment_names: config.environment_names.iter().cloned().collect(),
            max_handles: config.max_handles,
            max_output_bytes: config.max_output_bytes,
        });
    }
    Ok(scopes)
}

fn valid_relative_scope(path: &Path) -> bool {
    path == Path::new(".")
        || (!path.as_os_str().is_empty()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_))))
}

struct SharedAuthorizer<A>(Rc<RefCell<A>>);

impl<A> Clone for SharedAuthorizer<A> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

impl<A> SharedAuthorizer<A> {
    fn new(value: A) -> Self {
        Self(Rc::new(RefCell::new(value)))
    }
}

impl<A: ExecutionAuthorizer> ExecutionAuthorizer for SharedAuthorizer<A> {
    fn authorize(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
        now: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
        self.0.borrow_mut().authorize(session, request, now)
    }
}

struct SharedAttempts<T>(Rc<RefCell<T>>);

impl<T> Clone for SharedAttempts<T> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

impl<T> SharedAttempts<T> {
    fn new(value: T) -> Self {
        Self(Rc::new(RefCell::new(value)))
    }
}

impl<T: AttemptValidator> AttemptValidator for SharedAttempts<T> {
    fn validate(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
    ) -> Result<(), AttemptRefusalV1> {
        self.0.borrow_mut().validate(session, request)
    }
}

struct GovernedAgentFileReader<A, T> {
    authorizer: SharedAuthorizer<A>,
    attempts: SharedAttempts<T>,
    service_session: AuthenticatedSessionV1,
    scopes: BTreeMap<[u8; 16], AgentFileReadScopeV1>,
}

impl<A, T> GovernedAgentFileReader<A, T> {
    fn new(
        authorizer: SharedAuthorizer<A>,
        attempts: SharedAttempts<T>,
        service_session: AuthenticatedSessionV1,
        scopes: Vec<AgentFileReadScopeV1>,
    ) -> Self {
        Self {
            authorizer,
            attempts,
            service_session,
            scopes: scopes
                .into_iter()
                .map(|scope| (scope.workspace, scope))
                .collect(),
        }
    }
}

impl<A: ExecutionAuthorizer, T: AttemptValidator> AgentClientFileReader
    for GovernedAgentFileReader<A, T>
{
    fn supports_agent_file_read(
        &self,
        request: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
    ) -> bool {
        self.scopes.get(&request.workspace).is_some_and(|scope| {
            profile.wire == AgentWireProfileV1::AgentClientProtocol
                && request.execution.profile == profile.harness_profile
                && request.execution.tools.contains(&scope.capability)
        })
    }

    fn read_agent_file(
        &mut self,
        request: &AgentFileReadRequestV1,
    ) -> Result<AgentFileReadReceiptV1, AgentFileReadRefusalV1> {
        let scope = self
            .scopes
            .get(&request.workspace)
            .ok_or(AgentFileReadRefusalV1::Denied)?;
        if request.execution.principal.into_bytes() != self.service_session.principal
            || !request.execution.tools.contains(&scope.capability)
        {
            return Err(AgentFileReadRefusalV1::Denied);
        }
        let authority = self
            .authorizer
            .authorize(&self.service_session, &request.execution, request.now)
            .map_err(|_| AgentFileReadRefusalV1::Denied)?;
        if !authority.tools.contains(&scope.capability) {
            return Err(AgentFileReadRefusalV1::Denied);
        }
        self.attempts
            .validate(&self.service_session, &request.execution)
            .map_err(|_| AgentFileReadRefusalV1::Denied)?;
        read_scoped_file(scope, request)
    }
}

fn read_scoped_file(
    scope: &AgentFileReadScopeV1,
    request: &AgentFileReadRequestV1,
) -> Result<AgentFileReadReceiptV1, AgentFileReadRefusalV1> {
    let requested = std::str::from_utf8(&request.path)
        .ok()
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .ok_or(AgentFileReadRefusalV1::Invalid)?;
    let canonical = fs::canonicalize(requested).map_err(|_| AgentFileReadRefusalV1::Failed)?;
    if !canonical.is_file()
        || !canonical.starts_with(&scope.workspace_path)
        || !scope.paths.iter().any(|root| {
            if root.directory {
                canonical.starts_with(&root.path)
            } else {
                canonical == root.path
            }
        })
    {
        return Err(AgentFileReadRefusalV1::Denied);
    }
    let mut file = fs::File::open(&canonical).map_err(|_| AgentFileReadRefusalV1::Failed)?;
    let read_limit = u64::try_from(scope.max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| AgentFileReadRefusalV1::Failed)?;
    if bytes.len() > scope.max_bytes {
        return Err(AgentFileReadRefusalV1::Limit);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| AgentFileReadRefusalV1::Invalid)?;
    let start = usize::try_from(request.line.unwrap_or(1).saturating_sub(1))
        .map_err(|_| AgentFileReadRefusalV1::Limit)?;
    let limit = request
        .limit
        .map(usize::try_from)
        .transpose()
        .map_err(|_| AgentFileReadRefusalV1::Limit)?
        .unwrap_or(usize::MAX);
    let content = text
        .split_inclusive('\n')
        .skip(start)
        .take(limit)
        .collect::<String>()
        .into_bytes();
    let relative = canonical
        .strip_prefix(&scope.workspace_path)
        .ok()
        .and_then(Path::to_str)
        .filter(|path| !path.is_empty())
        .ok_or(AgentFileReadRefusalV1::Invalid)?;
    Ok(AgentFileReadReceiptV1 {
        path: relative.as_bytes().to_vec(),
        content_digest: protocol::ContentDigestV1::new(Sha256::digest(&content).into()),
        content,
    })
}

struct GovernedAgentTerminal<A, T> {
    authorizer: SharedAuthorizer<A>,
    attempts: SharedAttempts<T>,
    service_session: AuthenticatedSessionV1,
    scopes: BTreeMap<[u8; 16], AgentTerminalScopeV1>,
    handles: BTreeMap<(protocol::AgentSessionIdV1, Vec<u8>), ProcessBoundaryV1>,
    next_handle: u64,
    startup_timeout: Duration,
    cancellation_timeout: Duration,
}

impl<A, T> GovernedAgentTerminal<A, T> {
    fn new(
        authorizer: SharedAuthorizer<A>,
        attempts: SharedAttempts<T>,
        service_session: AuthenticatedSessionV1,
        scopes: Vec<AgentTerminalScopeV1>,
        timeout: Duration,
    ) -> Self {
        Self {
            authorizer,
            attempts,
            service_session,
            scopes: scopes
                .into_iter()
                .map(|scope| (scope.workspace, scope))
                .collect(),
            handles: BTreeMap::new(),
            next_handle: 0,
            startup_timeout: timeout,
            cancellation_timeout: timeout,
        }
    }

    fn handle_key(
        session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> (protocol::AgentSessionIdV1, Vec<u8>) {
        (session, terminal_id.to_vec())
    }
}

impl<A: ExecutionAuthorizer, T: AttemptValidator> AgentClientTerminal
    for GovernedAgentTerminal<A, T>
{
    fn supports_agent_terminal(
        &self,
        request: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
    ) -> bool {
        self.scopes.get(&request.workspace).is_some_and(|scope| {
            profile.wire == AgentWireProfileV1::AgentClientProtocol
                && request.execution.profile == profile.harness_profile
                && request.execution.tools.contains(&scope.capability)
        })
    }

    fn create_agent_terminal(
        &mut self,
        request: &AgentTerminalCreateRequestV1,
    ) -> Result<AgentTerminalCreatedV1, AgentTerminalRefusalV1> {
        let scope = self
            .scopes
            .get(&request.workspace)
            .cloned()
            .ok_or(AgentTerminalRefusalV1::Denied)?;
        if request.execution.principal.into_bytes() != self.service_session.principal
            || !request.execution.tools.contains(&scope.capability)
        {
            return Err(AgentTerminalRefusalV1::Denied);
        }
        let authority = self
            .authorizer
            .authorize(&self.service_session, &request.execution, request.now)
            .map_err(|_| AgentTerminalRefusalV1::Denied)?;
        if !authority.tools.contains(&scope.capability) {
            return Err(AgentTerminalRefusalV1::Denied);
        }
        self.attempts
            .validate(&self.service_session, &request.execution)
            .map_err(|_| AgentTerminalRefusalV1::Denied)?;
        if self
            .handles
            .keys()
            .filter(|(session, _)| *session == request.session)
            .count()
            >= scope.max_handles
        {
            return Err(AgentTerminalRefusalV1::Capacity);
        }
        let command =
            std::str::from_utf8(&request.command).map_err(|_| AgentTerminalRefusalV1::Invalid)?;
        let arguments = request
            .arguments
            .iter()
            .map(|value| {
                std::str::from_utf8(value)
                    .map(str::to_owned)
                    .map_err(|_| AgentTerminalRefusalV1::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let approved = scope
            .commands
            .get(command)
            .ok_or(AgentTerminalRefusalV1::Denied)?;
        if !arguments.starts_with(&approved.argument_prefix)
            || dangerous_terminal_flag(&approved.program, &arguments)
        {
            return Err(AgentTerminalRefusalV1::Denied);
        }
        let cwd = std::str::from_utf8(&request.cwd)
            .ok()
            .map(Path::new)
            .filter(|path| path.is_absolute())
            .ok_or(AgentTerminalRefusalV1::Invalid)?;
        let cwd = fs::canonicalize(cwd).map_err(|_| AgentTerminalRefusalV1::Invalid)?;
        if !cwd.is_dir() || !cwd.starts_with(&scope.workspace_path) {
            return Err(AgentTerminalRefusalV1::Denied);
        }
        let mut environment = Vec::new();
        let mut environment_names = BTreeSet::new();
        for (name, value) in &request.environment {
            let name = std::str::from_utf8(name)
                .map_err(|_| AgentTerminalRefusalV1::Invalid)?
                .to_owned();
            let value = std::str::from_utf8(value)
                .map_err(|_| AgentTerminalRefusalV1::Invalid)?
                .to_owned();
            if !scope.environment_names.contains(&name) || !environment_names.insert(name.clone()) {
                return Err(AgentTerminalRefusalV1::Denied);
            }
            environment.push((name, value));
        }
        let output_byte_limit = request
            .output_byte_limit
            .map(usize::try_from)
            .transpose()
            .map_err(|_| AgentTerminalRefusalV1::Invalid)?
            .unwrap_or(scope.max_output_bytes);
        if output_byte_limit > scope.max_output_bytes {
            return Err(AgentTerminalRefusalV1::Denied);
        }
        let program = approved
            .program
            .to_str()
            .ok_or(AgentTerminalRefusalV1::Invalid)?
            .to_owned();
        let mut argv = Vec::with_capacity(arguments.len().saturating_add(1));
        argv.push(program);
        argv.extend(arguments);
        let boundary = ProcessBoundaryV1::start(&ProcessBoundaryLaunchV1 {
            boundary_program: scope.boundary_program,
            argv,
            cwd,
            environment,
            output_byte_limit,
            startup_timeout: self.startup_timeout,
            cancellation_timeout: self.cancellation_timeout,
        })
        .map_err(|_| AgentTerminalRefusalV1::Failed)?;
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(AgentTerminalRefusalV1::Capacity)?;
        let terminal_id = terminal_identity(request.session, self.next_handle);
        if self
            .handles
            .insert(Self::handle_key(request.session, &terminal_id), boundary)
            .is_some()
        {
            return Err(AgentTerminalRefusalV1::Failed);
        }
        Ok(AgentTerminalCreatedV1 { terminal_id })
    }

    fn output_agent_terminal(
        &mut self,
        session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<AgentTerminalOutputV1, AgentTerminalRefusalV1> {
        let boundary = self
            .handles
            .get_mut(&Self::handle_key(session, terminal_id))
            .ok_or(AgentTerminalRefusalV1::NotFound)?;
        let output = boundary
            .output()
            .map_err(|_| AgentTerminalRefusalV1::Failed)?;
        Ok(AgentTerminalOutputV1 {
            output: output.output,
            truncated: output.truncated,
            exit: output.exit.map(agent_terminal_exit),
        })
    }

    fn poll_agent_terminal_exit(
        &mut self,
        session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<Option<AgentTerminalExitV1>, AgentTerminalRefusalV1> {
        self.handles
            .get_mut(&Self::handle_key(session, terminal_id))
            .ok_or(AgentTerminalRefusalV1::NotFound)?
            .poll_exit()
            .map(|exit| exit.map(agent_terminal_exit))
            .map_err(|_| AgentTerminalRefusalV1::Failed)
    }

    fn kill_agent_terminal(
        &mut self,
        session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<(), AgentTerminalRefusalV1> {
        let boundary = self
            .handles
            .get_mut(&Self::handle_key(session, terminal_id))
            .ok_or(AgentTerminalRefusalV1::NotFound)?;
        boundary
            .cancel()
            .map(|_| ())
            .map_err(|_| AgentTerminalRefusalV1::Failed)
    }

    fn release_agent_terminal(
        &mut self,
        session: protocol::AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<(), AgentTerminalRefusalV1> {
        let mut boundary = self
            .handles
            .remove(&Self::handle_key(session, terminal_id))
            .ok_or(AgentTerminalRefusalV1::NotFound)?;
        if boundary
            .poll_exit()
            .map_err(|_| AgentTerminalRefusalV1::Failed)?
            .is_none()
        {
            boundary
                .cancel()
                .map_err(|_| AgentTerminalRefusalV1::Failed)?;
        }
        Ok(())
    }

    fn release_agent_terminals(&mut self, session: protocol::AgentSessionIdV1) {
        let terminal_ids = self
            .handles
            .keys()
            .filter(|(owned_session, _)| *owned_session == session)
            .map(|(_, terminal_id)| terminal_id.clone())
            .collect::<Vec<_>>();
        for terminal_id in terminal_ids {
            let _ = self.release_agent_terminal(session, &terminal_id);
        }
    }
}

fn terminal_identity(session: protocol::AgentSessionIdV1, sequence: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"daimon-terminal-v1");
    hasher.update(session.into_bytes());
    hasher.update(sequence.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut value = String::from("terminal-");
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in &digest[..18] {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value.into_bytes()
}

fn agent_terminal_exit(exit: ProcessBoundaryExitV1) -> AgentTerminalExitV1 {
    AgentTerminalExitV1 {
        exit_code: exit.exit_code,
        signal: exit
            .signal
            .and_then(signal_name)
            .map(str::as_bytes)
            .map(Vec::from),
    }
}

fn signal_name(signal: i32) -> Option<&'static str> {
    Some(match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => return None,
    })
}

fn dangerous_terminal_flag(program: &Path, arguments: &[String]) -> bool {
    let Some(binary) = program.file_name().and_then(|value| value.to_str()) else {
        return true;
    };
    let flags: &[&str] = match binary {
        "mix" | "elixir" | "iex" => &["-e", "--eval"],
        "git" => &["-c", "--exec", "--upload-pack", "--receive-pack"],
        "python" | "python3" | "sh" | "bash" | "zsh" => &["-c"],
        "ruby" | "perl" => &["-e"],
        "node" => &["-e", "--eval"],
        "php" => &["-r"],
        _ => &[],
    };
    arguments.iter().any(|argument| {
        flags.iter().any(|flag| {
            argument == flag
                || argument.starts_with(&format!("{flag}="))
                || (flag.len() == 2 && argument.starts_with(flag))
        })
    })
}

pub fn run(config: ValidatedConfigV1) -> Result<(), Box<dyn std::error::Error>> {
    run_with_shutdown(config, None)
}

/// Runs the production agent service under an explicit one-byte supervisor
/// channel. Only `x` requests shutdown; EOF and every other byte leave the
/// service running. The wake connection carries no application command and is
/// used only to release the blocking local accept after the request is set.
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
    let mut scopes = config
        .profiles
        .iter()
        .map(|profile| aegis_protocol::ScopeV1 {
            engine: aegis_protocol::EngineNamespaceV1::Daimon,
            resource: profile.harness_profile.into_bytes(),
            actions: 1 << aegis_protocol::ActionV1::Execute as u8,
        })
        .collect::<Vec<_>>();
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
    let service_session = AuthenticatedSessionV1 {
        principal: config.principal,
        authority_context: grant_context(grant),
    };
    let authorizer =
        SharedAuthorizer::new(AegisAuthorizer::new(authority, grant, config.principal));
    let chronos_limits = chronos_limits();
    let attempts = SharedAttempts::new(
        ChronosAttemptValidator::new(
            ChronosUnixPort {
                path: config.raw.chronos_socket.clone(),
                limits: chronos_limits,
                timeout,
            },
            chronos_limits,
            config.bindings.len(),
            config.bindings,
        )
        .map_err(|_| failure("invalid Chronos bindings"))?,
    );
    let profiles =
        StaticAgentProfileRouter::try_new(config.profiles.len(), config.profiles.clone())
            .map_err(|_| failure("invalid agent profile registry"))?;
    let file_reader = (!config.file_read_scopes.is_empty()).then(|| {
        Box::new(GovernedAgentFileReader::new(
            authorizer.clone(),
            attempts.clone(),
            service_session.clone(),
            config.file_read_scopes,
        )) as Box<dyn AgentClientFileReader>
    });
    let terminal = (!config.terminal_scopes.is_empty()).then(|| {
        Box::new(GovernedAgentTerminal::new(
            authorizer.clone(),
            attempts.clone(),
            service_session.clone(),
            config.terminal_scopes,
            timeout,
        )) as Box<dyn AgentClientTerminal>
    });
    let provider = build_provider_router(&config.raw, &config.profiles, file_reader, terminal)
        .map_err(|_| failure("invalid agent provider configuration"))?;
    let store_limits =
        agent_store_limits(config.raw.max_store_bytes, config.raw.max_agent_sessions);
    let store = if config.raw.store_directory.exists() {
        daimon_local::open_existing_agent(&config.raw.store_directory, store_limits)
    } else {
        daimon_local::create_new_agent(&config.raw.store_directory, store_limits)
    }
    .map_err(|_| failure("agent store unavailable"))?;
    let service = AgentService::open(
        daimon_harness::Limits::default(),
        AgentServiceLimitsV1 {
            max_service_sessions: config.raw.max_service_sessions,
            max_agent_sessions: config.raw.max_agent_sessions,
            max_events_per_page: 256,
        },
        authorizer,
        attempts,
        profiles,
        config.context,
        provider,
        store,
    )
    .map_err(|_| failure("agent service recovery failed"))?;
    let mut daemon = AgentDaemon::bind_new(
        &config.raw.daimon_socket,
        service,
        FixedAuthenticator {
            principal: config.principal,
            authority_context: grant_context(grant),
        },
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
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
        served.map_err(|_| failure("agent daemon connection failed"))?;
    }
}

fn profile_snapshot(config: &ProviderConfigV1) -> Result<AgentProfileSnapshotV1, ConfigErrorV1> {
    if !config.program.is_absolute()
        || config.arguments.len() > 256
        || config.inherited_environment_names.len() > 128
        || config
            .inherited_environment_names
            .iter()
            .any(|name| !valid_env_name(name))
        || config
            .inherited_environment_names
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != config.inherited_environment_names.len()
        || config
            .acp_agent_authentication_method
            .as_deref()
            .is_some_and(|value| {
                !matches!(config.transport, TransportConfigV1::Acp)
                    || value.is_empty()
                    || value.len() > 256
                    || value.chars().any(char::is_control)
            })
    {
        return Err(ConfigErrorV1::Invalid);
    }
    process_isolation(config)?;
    let provider = protocol::ProviderProfileIdV1::new(hex_id(&config.provider_id)?);
    let harness_profile = protocol::HarnessProfileIdV1::new(hex_id(&config.harness_profile_id)?);
    let command_digest = command_digest(config)?;
    let policy_digest = digest(&config.policy_digest)?;
    let wire = match config.transport {
        TransportConfigV1::Acp => AgentWireProfileV1::AgentClientProtocol,
        TransportConfigV1::ClaudeStreamJson => AgentWireProfileV1::ClaudeAgentStreamJson,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"daimon-agent-profile-v1");
    hasher.update(provider.into_bytes());
    hasher.update(harness_profile.into_bytes());
    hasher.update([match wire {
        AgentWireProfileV1::AgentClientProtocol => 0,
        AgentWireProfileV1::ClaudeAgentStreamJson => 1,
    }]);
    hasher.update(command_digest.into_bytes());
    hasher.update(policy_digest.into_bytes());
    Ok(AgentProfileSnapshotV1 {
        provider,
        harness_profile,
        wire,
        command_digest,
        policy_digest,
        document_digest: protocol::ContentDigestV1::new(hasher.finalize().into()),
    })
}

fn command_digest(config: &ProviderConfigV1) -> Result<protocol::ContentDigestV1, ConfigErrorV1> {
    let program = config
        .program
        .to_str()
        .ok_or(ConfigErrorV1::Invalid)?
        .as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"daimon-agent-launch-v2");
    hash_field(&mut hasher, program)?;
    hash_count(&mut hasher, config.arguments.len())?;
    for argument in &config.arguments {
        hash_field(&mut hasher, argument.as_bytes())?;
    }
    hash_count(&mut hasher, config.inherited_environment_names.len())?;
    for name in &config.inherited_environment_names {
        hash_field(&mut hasher, name.as_bytes())?;
    }
    match &config.acp_agent_authentication_method {
        Some(method) => {
            hasher.update([1]);
            hash_field(&mut hasher, method.as_bytes())?;
        }
        None => hasher.update([0]),
    }
    let (isolation_kind, isolation_digest) = process_isolation(config)?.identity();
    hasher.update([isolation_kind]);
    if let Some(isolation_digest) = isolation_digest {
        hasher.update(isolation_digest);
    }
    Ok(protocol::ContentDigestV1::new(hasher.finalize().into()))
}

fn process_isolation(config: &ProviderConfigV1) -> Result<ProcessIsolationV1, ConfigErrorV1> {
    match &config.isolation {
        IsolationConfigV1::Direct => Ok(ProcessIsolationV1::Direct),
        IsolationConfigV1::MacosSeatbelt {
            policy_path,
            policy_digest,
        } => {
            if !policy_path.is_absolute() {
                return Err(ConfigErrorV1::Invalid);
            }
            let policy = fs::read(policy_path).map_err(|_| ConfigErrorV1::Io)?;
            ProcessIsolationV1::macos_seatbelt(policy, digest(policy_digest)?.into_bytes())
                .map_err(|_| ConfigErrorV1::Invalid)
        }
    }
}

fn hash_count(hasher: &mut Sha256, value: usize) -> Result<(), ConfigErrorV1> {
    let value = u64::try_from(value).map_err(|_| ConfigErrorV1::Invalid)?;
    hasher.update(value.to_le_bytes());
    Ok(())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<(), ConfigErrorV1> {
    hash_count(hasher, value.len())?;
    hasher.update(value);
    Ok(())
}

fn build_provider_router(
    config: &ConfigV1,
    profiles: &[AgentProfileSnapshotV1],
    mut file_reader: Option<Box<dyn AgentClientFileReader>>,
    mut terminal: Option<Box<dyn AgentClientTerminal>>,
) -> Result<AgentProviderRouter, ConfigErrorV1> {
    let workspaces = config
        .workspaces
        .iter()
        .map(|workspace| {
            if !workspace.path.is_absolute() {
                return Err(ConfigErrorV1::Invalid);
            }
            Ok((hex_id(&workspace.identity)?, workspace.path.clone()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if workspaces
        .iter()
        .map(|(id, _)| id)
        .collect::<BTreeSet<_>>()
        .len()
        != workspaces.len()
    {
        return Err(ConfigErrorV1::Invalid);
    }
    let mut acp_profiles = Vec::new();
    let mut claude_profiles = Vec::new();
    for (raw, snapshot) in config.providers.iter().zip(profiles) {
        match raw.transport {
            TransportConfigV1::Acp => acp_profiles.push(AcpLaunchProfileV1 {
                snapshot: snapshot.clone(),
                program: raw.program.clone(),
                arguments: raw.arguments.iter().map(OsString::from).collect(),
                inherited_environment_names: raw
                    .inherited_environment_names
                    .iter()
                    .map(OsString::from)
                    .collect(),
                agent_authentication_method: raw.acp_agent_authentication_method.clone(),
                isolation: process_isolation(raw)?,
            }),
            TransportConfigV1::ClaudeStreamJson => {
                claude_profiles.push(ClaudeLaunchProfileV1 {
                    snapshot: snapshot.clone(),
                    program: raw.program.clone(),
                    arguments: raw.arguments.iter().map(OsString::from).collect(),
                    inherited_environment_names: raw
                        .inherited_environment_names
                        .iter()
                        .map(OsString::from)
                        .collect(),
                    isolation: process_isolation(raw)?,
                });
            }
        }
    }
    let mut routes = Vec::new();
    if !acp_profiles.is_empty() {
        let documents = acp_profiles
            .iter()
            .map(|profile| profile.snapshot.document_digest)
            .collect();
        let limits = AcpLimitsV1 {
            max_sessions: config.max_agent_sessions,
            ..AcpLimitsV1::default()
        };
        let workspaces = workspaces
            .iter()
            .map(|(identity, path)| AcpWorkspaceV1 {
                identity: *identity,
                path: path.clone(),
            })
            .collect();
        let provider = match (file_reader.take(), terminal.take()) {
            (Some(reader), Some(terminal)) => AcpProvider::try_new_with_client_ports(
                limits,
                acp_profiles,
                workspaces,
                reader,
                terminal,
            ),
            (Some(reader), None) => {
                AcpProvider::try_new_with_file_reader(limits, acp_profiles, workspaces, reader)
            }
            (None, Some(terminal)) => {
                AcpProvider::try_new_with_terminal(limits, acp_profiles, workspaces, terminal)
            }
            (None, None) => AcpProvider::try_new(limits, acp_profiles, workspaces),
        }
        .map_err(|_| ConfigErrorV1::Invalid)?;
        routes.push(AgentProviderRouteV1 {
            profile_documents: documents,
            provider: Box::new(provider),
        });
    }
    if !claude_profiles.is_empty() {
        let documents = claude_profiles
            .iter()
            .map(|profile| profile.snapshot.document_digest)
            .collect();
        let provider = ClaudeProvider::try_new(
            ClaudeLimitsV1 {
                max_sessions: config.max_agent_sessions,
                ..ClaudeLimitsV1::default()
            },
            claude_profiles,
            workspaces
                .iter()
                .map(|(identity, path)| ClaudeWorkspaceV1 {
                    identity: *identity,
                    path: path.clone(),
                })
                .collect(),
        )
        .map_err(|_| ConfigErrorV1::Invalid)?;
        routes.push(AgentProviderRouteV1 {
            profile_documents: documents,
            provider: Box::new(provider),
        });
    }
    AgentProviderRouter::try_new(config.max_agent_sessions, routes)
        .map_err(|_| ConfigErrorV1::Invalid)
}

enum AgentContextBinding {
    Static(protocol::ContextEvidenceV1),
    Vellum(VellumContextBinding),
}

#[derive(Clone)]
struct VellumContextBinding {
    socket: PathBuf,
    credential: PathBuf,
    workspace_id: u64,
    document_ordinal: u64,
    expected_revision: u64,
}

struct AgentContext {
    bindings: BTreeMap<protocol::ContextReferenceIdV1, AgentContextBinding>,
    max_bytes: usize,
    timeout: Duration,
}

impl AgentContext {
    fn try_new(
        config: &[ContextConfigV1],
        vellum: &[VellumContextConfigV1],
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Self, ConfigErrorV1> {
        let mut bindings = BTreeMap::new();
        for item in config {
            let reference = protocol::ContextReferenceIdV1::new(hex_id(&item.reference)?);
            if matches!(item.kind, ContextKindConfigV1::VellumDocument) {
                return Err(ConfigErrorV1::Invalid);
            }
            let bytes = item.text.as_bytes().to_vec();
            if bytes.is_empty() || bytes.len() > max_bytes {
                return Err(ConfigErrorV1::Invalid);
            }
            let grounding = item
                .grounding
                .as_ref()
                .map(|value| {
                    Ok(protocol::GroundingEvidenceV1 {
                        depth: match value.depth {
                            GroundingDepthConfigV1::Ambient => protocol::GroundingDepthV1::Ambient,
                            GroundingDepthConfigV1::Activated => {
                                protocol::GroundingDepthV1::Activated
                            }
                            GroundingDepthConfigV1::Reference => {
                                protocol::GroundingDepthV1::Reference
                            }
                        },
                        grounding_digest: digest(&value.grounding_digest)?,
                        surface_digest: digest(&value.surface_digest)?,
                    })
                })
                .transpose()?;
            let value = protocol::ContextEvidenceV1 {
                reference,
                kind: match item.kind {
                    ContextKindConfigV1::AgoraMessage => protocol::ContextKindV1::AgoraMessage,
                    ContextKindConfigV1::ChronosWork => protocol::ContextKindV1::ChronosWork,
                    ContextKindConfigV1::VellumDocument => protocol::ContextKindV1::VellumDocument,
                },
                source_digest: protocol::ContentDigestV1::new(Sha256::digest(&bytes).into()),
                bytes,
                grounding,
            };
            if bindings
                .insert(reference, AgentContextBinding::Static(value))
                .is_some()
            {
                return Err(ConfigErrorV1::Invalid);
            }
        }
        for item in vellum {
            if !item.socket.is_absolute()
                || !item.credential.is_absolute()
                || item.workspace_id == 0
                || item.document_ordinal == 0
            {
                return Err(ConfigErrorV1::Invalid);
            }
            let reference = protocol::ContextReferenceIdV1::new(hex_id(&item.reference)?);
            if bindings
                .insert(
                    reference,
                    AgentContextBinding::Vellum(VellumContextBinding {
                        socket: item.socket.clone(),
                        credential: item.credential.clone(),
                        workspace_id: item.workspace_id,
                        document_ordinal: item.document_ordinal,
                        expected_revision: item.expected_revision,
                    }),
                )
                .is_some()
            {
                return Err(ConfigErrorV1::Invalid);
            }
        }
        Ok(Self {
            bindings,
            max_bytes,
            timeout,
        })
    }

    fn resolve_vellum(
        &self,
        reference: protocol::ContextReferenceIdV1,
        binding: &VellumContextBinding,
    ) -> Result<protocol::ContextEvidenceV1, ContextRefusalV1> {
        let record = LocalCredentialStoreV1::default()
            .load(&binding.credential)
            .map_err(|_| ContextRefusalV1::Unavailable)?;
        let connector = AuthenticatedUnixConnector::with_provider_and_timeout(
            binding.socket.clone(),
            LocalCredentialClaimProviderV1::new(record),
            self.timeout,
        )
        .map_err(|_| ContextRefusalV1::InvalidEvidence)?;
        let transport = RemoteTransport::new(connector, TransportLimits::reference())
            .map_err(|_| ContextRefusalV1::InvalidEvidence)?;
        let mut client =
            WorkspaceClientV1::connect(transport).map_err(|_| ContextRefusalV1::Unavailable)?;
        client
            .refresh_inventory()
            .map_err(|_| ContextRefusalV1::Unavailable)?;
        let workspace =
            WorkspaceIdV1::new(binding.workspace_id).ok_or(ContextRefusalV1::InvalidEvidence)?;
        if client.projection().inventory().map(|value| value.workspace) != Some(workspace) {
            return Err(ContextRefusalV1::Unavailable);
        }
        let document = WorkspaceDocumentIdV1::new(workspace, binding.document_ordinal)
            .ok_or(ContextRefusalV1::InvalidEvidence)?;
        client
            .select_document(document)
            .map_err(|_| ContextRefusalV1::Unavailable)?;
        client
            .refresh_snapshot()
            .map_err(|_| ContextRefusalV1::Unavailable)?;
        let snapshot = client
            .projection()
            .snapshot()
            .cloned()
            .ok_or(ContextRefusalV1::Unavailable)?;
        client
            .disconnect()
            .map_err(|_| ContextRefusalV1::Unavailable)?;
        vellum_evidence(reference, binding, &snapshot, self.max_bytes)
    }

    fn select(
        &mut self,
        references: &[protocol::ContextReferenceIdV1],
    ) -> Result<Vec<protocol::ContextEvidenceV1>, ContextRefusalV1> {
        let mut seen = BTreeSet::new();
        let mut selected = Vec::with_capacity(references.len());
        for reference in references {
            if !seen.insert(*reference) {
                return Err(ContextRefusalV1::InvalidEvidence);
            }
            let value = match self.bindings.get(reference) {
                Some(AgentContextBinding::Static(value)) => value.clone(),
                Some(AgentContextBinding::Vellum(binding)) => {
                    let binding = binding.clone();
                    self.resolve_vellum(*reference, &binding)?
                }
                None => return Err(ContextRefusalV1::Unavailable),
            };
            selected.push(value);
        }
        let total = selected
            .iter()
            .try_fold(0usize, |total, value| total.checked_add(value.bytes.len()));
        if total.is_none_or(|total| total > self.max_bytes) {
            return Err(ContextRefusalV1::Limit);
        }
        Ok(selected)
    }
}

fn vellum_evidence(
    reference: protocol::ContextReferenceIdV1,
    binding: &VellumContextBinding,
    snapshot: &SnapshotV1,
    max_bytes: usize,
) -> Result<protocol::ContextEvidenceV1, ContextRefusalV1> {
    if snapshot.revision != binding.expected_revision {
        return Err(ContextRefusalV1::InvalidEvidence);
    }
    let bytes = snapshot.text.as_bytes().to_vec();
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(ContextRefusalV1::Limit);
    }
    Ok(protocol::ContextEvidenceV1 {
        reference,
        kind: protocol::ContextKindV1::VellumDocument,
        source_digest: protocol::ContentDigestV1::new(Sha256::digest(&bytes).into()),
        bytes,
        grounding: None,
    })
}

impl AgentContextAssembler for AgentContext {
    fn assemble_agent_context(
        &mut self,
        _service_session: &AuthenticatedSessionV1,
        request: &AgentOpenRequestV1,
        _profile: &AgentProfileSnapshotV1,
    ) -> Result<Vec<protocol::ContextEvidenceV1>, ContextRefusalV1> {
        self.select(&request.execution.context)
    }

    fn assemble_agent_turn_context(
        &mut self,
        _service_session: &AuthenticatedSessionV1,
        request: &AgentTurnRequestV1,
        _profile: &AgentProfileSnapshotV1,
    ) -> Result<Vec<protocol::ContextEvidenceV1>, ContextRefusalV1> {
        self.select(&request.execution.context)
    }
}

struct FixedAuthenticator {
    principal: [u8; 16],
    authority_context: [u8; 16],
}

impl Authenticator for FixedAuthenticator {
    type Error = Infallible;

    fn authenticate(
        &mut self,
        _stream: &UnixStream,
    ) -> Result<AuthenticatedSessionV1, Self::Error> {
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

fn agent_store_limits(max_bytes: usize, max_sessions: usize) -> AgentStoreLimitsV1 {
    AgentStoreLimitsV1 {
        max_bytes,
        max_sessions,
        ..AgentStoreLimitsV1::default()
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
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn failure(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}

const fn default_io_timeout_ms() -> u64 {
    5_000
}
const fn default_max_agent_sessions() -> usize {
    1_024
}
const fn default_max_service_sessions() -> usize {
    256
}
const fn default_max_requests() -> usize {
    64
}
const fn default_max_store_bytes() -> usize {
    64 * 1024 * 1024
}
const fn default_max_context_bytes() -> usize {
    8 * 1024 * 1024
}
const fn default_max_file_read_bytes() -> usize {
    1024 * 1024
}
const fn default_max_terminal_handles() -> usize {
    8
}
const fn default_max_terminal_output_bytes() -> usize {
    1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    struct ExactAuthorizer {
        calls: Rc<Cell<usize>>,
        last_now: Rc<Cell<u64>>,
        deny: Rc<Cell<bool>>,
    }

    impl ExecutionAuthorizer for ExactAuthorizer {
        fn authorize(
            &mut self,
            _: &AuthenticatedSessionV1,
            request: &protocol::ExecuteRequestV1,
            now: u64,
        ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
            self.calls.set(self.calls.get() + 1);
            self.last_now.set(now);
            if self.deny.get() {
                return Err(AuthorityRefusalV1::Expired);
            }
            Ok(AuthorityGrantV1 {
                decision_id: [90; 16],
                expires_at: now,
                tools: request.tools.clone(),
            })
        }
    }

    struct ExactAttempts(Rc<Cell<usize>>);

    impl AttemptValidator for ExactAttempts {
        fn validate(
            &mut self,
            _: &AuthenticatedSessionV1,
            _: &protocol::ExecuteRequestV1,
        ) -> Result<(), AttemptRefusalV1> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    fn agent_execution(capability: protocol::ToolCapabilityIdV1) -> protocol::ExecuteRequestV1 {
        protocol::ExecuteRequestV1 {
            execution_id: protocol::ExecutionIdV1::new([81; 16]),
            task_attempt: protocol::TaskAttemptRefV1 {
                task_key: [82; 16],
                task_incarnation: 3,
                attempt_number: 4,
            },
            principal: protocol::PrincipalIdV1::new([1; 16]),
            profile: protocol::HarnessProfileIdV1::new([3; 16]),
            idempotency_key: protocol::IdempotencyKeyV1::new([83; 16]),
            context: Vec::new(),
            tools: vec![capability],
            budget: protocol::ExecutionBudgetV1 {
                max_elapsed_millis: 100,
                max_input_tokens: 100,
                max_output_tokens: 100,
                max_tool_calls: 1,
                max_context_bytes: 1024,
                max_output_bytes: 1024,
            },
        }
    }

    fn provider(seed: u8, transport: TransportConfigV1) -> ProviderConfigV1 {
        ProviderConfigV1 {
            provider_id: format!("{seed:02x}").repeat(16),
            harness_profile_id: format!("{:02x}", seed + 1).repeat(16),
            policy_digest: format!("sha256:{}", format!("{:02x}", seed + 2).repeat(32)),
            program: PathBuf::from(if matches!(transport, TransportConfigV1::Acp) {
                "/usr/local/bin/codex-acp"
            } else {
                "/usr/local/bin/claude"
            }),
            arguments: Vec::new(),
            inherited_environment_names: Vec::new(),
            acp_agent_authentication_method: None,
            isolation: IsolationConfigV1::Direct,
            transport,
        }
    }

    fn config() -> ConfigV1 {
        ConfigV1 {
            principal: "01010101010101010101010101010101".to_owned(),
            aegis_socket: PathBuf::from("/tmp/aegis-agent-test.sock"),
            aegis_expected_epoch: 0,
            aegis_grant_now: 1,
            aegis_grant_expires_at: 1_000,
            chronos_socket: PathBuf::from("/tmp/chronos-agent-test.sock"),
            daimon_socket: PathBuf::from("/tmp/daimon-agent-test.sock"),
            store_directory: PathBuf::from("/tmp/daimon-agent-test-store"),
            providers: vec![
                provider(2, TransportConfigV1::Acp),
                provider(12, TransportConfigV1::ClaudeStreamJson),
            ],
            workspaces: vec![WorkspaceConfigV1 {
                identity: "20202020202020202020202020202020".to_owned(),
                path: PathBuf::from("/tmp"),
                acp_file_read: None,
                acp_terminal: None,
            }],
            task_bindings: vec![TaskBindingConfigV1 {
                external_task_key: "30303030303030303030303030303030".to_owned(),
                chronos_task_id: "agent-test".to_owned(),
            }],
            tool_capabilities: Vec::new(),
            context: vec![ContextConfigV1 {
                reference: "40404040404040404040404040404040".to_owned(),
                kind: ContextKindConfigV1::ChronosWork,
                text: "exact grounded work".to_owned(),
                grounding: Some(GroundingConfigV1 {
                    depth: GroundingDepthConfigV1::Activated,
                    grounding_digest: format!("sha256:{}", "51".repeat(32)),
                    surface_digest: format!("sha256:{}", "52".repeat(32)),
                }),
            }],
            vellum_context: Vec::new(),
            io_timeout_ms: 1_000,
            max_agent_sessions: 8,
            max_service_sessions: 4,
            max_requests_per_connection: 8,
            max_store_bytes: 1024 * 1024,
            max_context_bytes: 1024,
        }
    }

    #[test]
    fn strict_mixed_provider_configuration_validates_without_external_contact() {
        let validated = validate(config()).unwrap();
        assert_eq!(validated.profiles.len(), 2);
        assert_eq!(
            validated.profiles[0].wire,
            AgentWireProfileV1::AgentClientProtocol
        );
        assert_eq!(
            validated.profiles[1].wire,
            AgentWireProfileV1::ClaudeAgentStreamJson
        );
        assert_ne!(
            validated.profiles[0].document_digest,
            validated.profiles[1].document_digest
        );
    }

    #[test]
    fn acp_file_read_scope_requires_granted_capability_and_refuses_symlink_escape() {
        let root =
            std::env::temp_dir().join(format!("daimon-agent-read-scope-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("daimon-agent-read-outside-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("allowed.txt"), "allowed\n").unwrap();
        fs::write(&outside, "outside\n").unwrap();
        symlink(&outside, root.join("escape.txt")).unwrap();

        let capability = "71717171717171717171717171717171".to_owned();
        let mut value = config();
        value.workspaces[0].path = root.clone();
        value.workspaces[0].acp_file_read = Some(AcpFileReadConfigV1 {
            capability: capability.clone(),
            paths: vec![PathBuf::from("allowed.txt")],
            max_bytes: 1024,
        });
        assert!(matches!(
            validate(value.clone()),
            Err(ConfigErrorV1::Invalid)
        ));

        value.tool_capabilities.push(capability);
        let validated = validate(value.clone()).unwrap();
        assert_eq!(validated.file_read_scopes.len(), 1);

        value.workspaces[0].acp_file_read.as_mut().unwrap().paths =
            vec![PathBuf::from("escape.txt")];
        assert!(matches!(validate(value), Err(ConfigErrorV1::Invalid)));

        fs::remove_dir_all(root).unwrap();
        fs::remove_file(outside).unwrap();
    }

    #[test]
    fn governed_file_reader_rechecks_continuation_time_authority_and_attempt() {
        let root =
            std::env::temp_dir().join(format!("daimon-agent-read-governor-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let path = root.join("evidence.txt");
        fs::write(&path, b"first\nsecond\n").unwrap();
        let canonical_root = fs::canonicalize(&root).unwrap();
        let capability = protocol::ToolCapabilityIdV1::new([71; 16]);
        let authority_calls = Rc::new(Cell::new(0));
        let attempt_calls = Rc::new(Cell::new(0));
        let last_now = Rc::new(Cell::new(0));
        let deny = Rc::new(Cell::new(false));
        let service_session = AuthenticatedSessionV1 {
            principal: [1; 16],
            authority_context: [2; 16],
        };
        let mut reader = GovernedAgentFileReader::new(
            SharedAuthorizer::new(ExactAuthorizer {
                calls: Rc::clone(&authority_calls),
                last_now: Rc::clone(&last_now),
                deny: Rc::clone(&deny),
            }),
            SharedAttempts::new(ExactAttempts(Rc::clone(&attempt_calls))),
            service_session,
            vec![AgentFileReadScopeV1 {
                workspace: [6; 16],
                workspace_path: canonical_root.clone(),
                capability,
                paths: vec![AgentFileReadRootV1 {
                    path: canonical_root,
                    directory: true,
                }],
                max_bytes: 1024,
            }],
        );
        let request = AgentFileReadRequestV1 {
            session: protocol::AgentSessionIdV1::new([72; 16]),
            turn: protocol::AgentTurnIdV1::new([73; 16]),
            workspace: [6; 16],
            execution: agent_execution(capability),
            now: 77,
            path: path.to_str().unwrap().as_bytes().to_vec(),
            line: Some(2),
            limit: Some(1),
        };
        let receipt = reader.read_agent_file(&request).unwrap();
        assert_eq!(receipt.path, b"evidence.txt");
        assert_eq!(receipt.content, b"second\n");
        assert_eq!(authority_calls.get(), 1);
        assert_eq!(attempt_calls.get(), 1);
        assert_eq!(last_now.get(), 77);

        deny.set(true);
        let mut expired = request;
        expired.now = 78;
        assert_eq!(
            reader.read_agent_file(&expired),
            Err(AgentFileReadRefusalV1::Denied)
        );
        assert_eq!(authority_calls.get(), 2);
        assert_eq!(attempt_calls.get(), 1);
        assert_eq!(last_now.get(), 78);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn terminal_scope_requires_granted_capability_and_exact_absolute_registry() {
        let capability = "74747474747474747474747474747474".to_owned();
        let mut value = config();
        value.workspaces[0].acp_terminal = Some(AcpTerminalConfigV1 {
            capability: capability.clone(),
            boundary_program: PathBuf::from("/bin/echo"),
            commands: vec![AcpTerminalCommandConfigV1 {
                command: "echo".to_owned(),
                program: PathBuf::from("/bin/echo"),
                argument_prefix: vec!["approved".to_owned()],
            }],
            environment_names: vec!["MODE".to_owned()],
            max_handles: 2,
            max_output_bytes: 1024,
        });
        assert!(matches!(
            validate(value.clone()),
            Err(ConfigErrorV1::Invalid)
        ));
        value.tool_capabilities.push(capability);
        let validated = validate(value.clone()).unwrap();
        assert_eq!(validated.terminal_scopes.len(), 1);

        value.workspaces[0]
            .acp_terminal
            .as_mut()
            .unwrap()
            .commands
            .push(AcpTerminalCommandConfigV1 {
                command: "echo".to_owned(),
                program: PathBuf::from("/bin/echo"),
                argument_prefix: Vec::new(),
            });
        assert!(matches!(validate(value), Err(ConfigErrorV1::Invalid)));
    }

    #[test]
    fn terminal_governor_rechecks_time_authority_attempt_and_dangerous_flags() {
        let workspace = fs::canonicalize("/tmp").unwrap();
        let program = fs::canonicalize("/bin/sh").unwrap();
        let capability = protocol::ToolCapabilityIdV1::new([74; 16]);
        let authority_calls = Rc::new(Cell::new(0));
        let attempt_calls = Rc::new(Cell::new(0));
        let last_now = Rc::new(Cell::new(0));
        let deny = Rc::new(Cell::new(false));
        let mut commands = BTreeMap::new();
        commands.insert(
            "sh".to_owned(),
            AgentTerminalCommandV1 {
                program,
                argument_prefix: Vec::new(),
            },
        );
        let mut terminal = GovernedAgentTerminal::new(
            SharedAuthorizer::new(ExactAuthorizer {
                calls: Rc::clone(&authority_calls),
                last_now: Rc::clone(&last_now),
                deny: Rc::clone(&deny),
            }),
            SharedAttempts::new(ExactAttempts(Rc::clone(&attempt_calls))),
            AuthenticatedSessionV1 {
                principal: [1; 16],
                authority_context: [2; 16],
            },
            vec![AgentTerminalScopeV1 {
                workspace: [6; 16],
                workspace_path: workspace.clone(),
                capability,
                boundary_program: PathBuf::from("/bin/echo"),
                commands,
                environment_names: BTreeSet::new(),
                max_handles: 1,
                max_output_bytes: 1024,
            }],
            Duration::from_secs(1),
        );
        let request = AgentTerminalCreateRequestV1 {
            session: protocol::AgentSessionIdV1::new([72; 16]),
            turn: protocol::AgentTurnIdV1::new([73; 16]),
            workspace: [6; 16],
            execution: agent_execution(capability),
            now: 91,
            command: b"sh".to_vec(),
            arguments: vec![b"-c".to_vec(), b"echo no".to_vec()],
            environment: Vec::new(),
            cwd: workspace.to_str().unwrap().as_bytes().to_vec(),
            output_byte_limit: Some(64),
        };
        assert_eq!(
            terminal.create_agent_terminal(&request),
            Err(AgentTerminalRefusalV1::Denied)
        );
        assert_eq!(authority_calls.get(), 1);
        assert_eq!(attempt_calls.get(), 1);
        assert_eq!(last_now.get(), 91);

        deny.set(true);
        let mut expired = request;
        expired.now = 92;
        expired.arguments = vec![b"safe.sh".to_vec()];
        assert_eq!(
            terminal.create_agent_terminal(&expired),
            Err(AgentTerminalRefusalV1::Denied)
        );
        assert_eq!(authority_calls.get(), 2);
        assert_eq!(attempt_calls.get(), 1);
        assert_eq!(last_now.get(), 92);
    }

    #[test]
    fn launch_or_policy_drift_changes_the_frozen_profile_document() {
        let original = provider(2, TransportConfigV1::Acp);
        let mut launch_drift = original.clone();
        launch_drift.arguments.push("--different".to_owned());
        let mut policy_drift = original.clone();
        policy_drift.policy_digest = format!("sha256:{}", "99".repeat(32));
        let mut authentication_drift = original.clone();
        authentication_drift.acp_agent_authentication_method = Some("provider-login".into());

        let original = profile_snapshot(&original).unwrap();
        assert_ne!(
            profile_snapshot(&launch_drift).unwrap().command_digest,
            original.command_digest
        );
        assert_ne!(
            profile_snapshot(&launch_drift).unwrap().document_digest,
            original.document_digest
        );
        assert_ne!(
            profile_snapshot(&policy_drift).unwrap().document_digest,
            original.document_digest
        );
        assert_ne!(
            profile_snapshot(&authentication_drift)
                .unwrap()
                .command_digest,
            original.command_digest
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_policy_is_digest_verified_and_part_of_frozen_launch_identity() {
        let path =
            std::env::temp_dir().join(format!("daimon-agent-seatbelt-{}.sb", std::process::id()));
        let policy = b"(version 1) (deny default)";
        fs::write(&path, policy).unwrap();
        let policy_digest = format!(
            "sha256:{}",
            Sha256::digest(policy)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let direct = provider(2, TransportConfigV1::Acp);
        let mut sandboxed = direct.clone();
        sandboxed.isolation = IsolationConfigV1::MacosSeatbelt {
            policy_path: path.clone(),
            policy_digest: policy_digest.clone(),
        };
        assert_ne!(
            profile_snapshot(&direct).unwrap().command_digest,
            profile_snapshot(&sandboxed).unwrap().command_digest
        );

        fs::write(&path, b"(version 1) (allow default)").unwrap();
        assert!(matches!(
            profile_snapshot(&sandboxed),
            Err(ConfigErrorV1::Invalid)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn aliases_environment_drift_and_context_overflow_fail_closed() {
        let mut aliased = config();
        aliased.providers[1].harness_profile_id = aliased.providers[0].harness_profile_id.clone();
        assert!(matches!(validate(aliased), Err(ConfigErrorV1::Invalid)));

        let mut duplicate_environment = config();
        duplicate_environment.providers[0].inherited_environment_names =
            vec!["CODEX_HOME".to_owned(), "CODEX_HOME".to_owned()];
        assert!(matches!(
            validate(duplicate_environment),
            Err(ConfigErrorV1::Invalid)
        ));

        let mut claude_auth = config();
        claude_auth.providers[1].acp_agent_authentication_method = Some("login".into());
        assert!(matches!(validate(claude_auth), Err(ConfigErrorV1::Invalid)));

        let mut invalid_auth = config();
        invalid_auth.providers[0].acp_agent_authentication_method = Some("bad\nmethod".into());
        assert!(matches!(
            validate(invalid_auth),
            Err(ConfigErrorV1::Invalid)
        ));

        let mut overflow = config();
        overflow.max_context_bytes = 4;
        assert!(matches!(validate(overflow), Err(ConfigErrorV1::Invalid)));
    }

    #[test]
    fn context_selection_preserves_exact_grounding_and_refuses_aliases() {
        let raw = config();
        let mut context = AgentContext::try_new(
            &raw.context,
            &raw.vellum_context,
            raw.max_context_bytes,
            Duration::from_secs(1),
        )
        .unwrap();
        let reference = protocol::ContextReferenceIdV1::new([0x40; 16]);
        let selected = context.select(&[reference]).unwrap();
        assert_eq!(selected[0].bytes, b"exact grounded work");
        assert_eq!(
            selected[0].grounding.unwrap().depth,
            protocol::GroundingDepthV1::Activated
        );
        assert_eq!(
            context.select(&[reference, reference]),
            Err(ContextRefusalV1::InvalidEvidence)
        );
        assert_eq!(
            context.select(&[protocol::ContextReferenceIdV1::new([0x41; 16])]),
            Err(ContextRefusalV1::Unavailable)
        );
    }

    #[test]
    fn vellum_context_binding_validates_offline_and_refuses_ambiguous_sources() {
        let mut raw = config();
        raw.vellum_context.push(VellumContextConfigV1 {
            reference: "41414141414141414141414141414141".to_owned(),
            socket: PathBuf::from("/tmp/not-contacted-vellum.sock"),
            credential: PathBuf::from("/tmp/not-read-vellum.credential"),
            workspace_id: 7,
            document_ordinal: 9,
            expected_revision: 11,
        });
        validate(raw.clone()).expect("offline binding validation must not contact Vellum");

        raw.vellum_context[0].reference = raw.context[0].reference.clone();
        assert!(matches!(validate(raw), Err(ConfigErrorV1::Invalid)));

        let mut copied = config();
        copied.context[0].kind = ContextKindConfigV1::VellumDocument;
        assert!(matches!(validate(copied), Err(ConfigErrorV1::Invalid)));
    }

    #[test]
    fn vellum_context_binding_requires_exact_nonzero_owner_identity() {
        let mut raw = config();
        raw.vellum_context.push(VellumContextConfigV1 {
            reference: "41414141414141414141414141414141".to_owned(),
            socket: PathBuf::from("relative.sock"),
            credential: PathBuf::from("/tmp/vellum.credential"),
            workspace_id: 1,
            document_ordinal: 1,
            expected_revision: 1,
        });
        assert!(matches!(validate(raw.clone()), Err(ConfigErrorV1::Invalid)));
        raw.vellum_context[0].socket = PathBuf::from("/tmp/vellum.sock");
        raw.vellum_context[0].document_ordinal = 0;
        assert!(matches!(validate(raw), Err(ConfigErrorV1::Invalid)));
    }

    #[test]
    fn vellum_context_accepts_revision_zero_and_refuses_exact_revision_drift() {
        let reference = protocol::ContextReferenceIdV1::new([0x41; 16]);
        let mut binding = VellumContextBinding {
            socket: PathBuf::from("/tmp/vellum.sock"),
            credential: PathBuf::from("/tmp/vellum.credential"),
            workspace_id: 1,
            document_ordinal: 1,
            expected_revision: 0,
        };
        let snapshot = SnapshotV1 {
            witness: vellum_sdk_client::protocol::VersionWitness::new(1).unwrap(),
            revision: 0,
            text: Arc::from("exact Vellum revision"),
        };
        let evidence = vellum_evidence(reference, &binding, &snapshot, 4_096).unwrap();
        assert_eq!(evidence.bytes, b"exact Vellum revision");
        assert_eq!(
            evidence.source_digest,
            protocol::ContentDigestV1::new(Sha256::digest(snapshot.text.as_bytes()).into())
        );

        binding.expected_revision = 1;
        assert_eq!(
            vellum_evidence(reference, &binding, &snapshot, 4_096),
            Err(ContextRefusalV1::InvalidEvidence)
        );
    }
}
