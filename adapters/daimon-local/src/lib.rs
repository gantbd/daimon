//! Exclusive private-directory wiring for Daimon's durable service checkpoint.

#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix {
    use daimon_checkpoint::agent::{AgentStoreLimitsV1, CheckpointAgentSessionStore};
    use daimon_checkpoint::model::{CheckpointModelExecutionStore, ModelStoreLimitsV1};
    use daimon_checkpoint::{CheckpointExecutionStore, StoreErrorV1, StoreLimitsV1};
    use keystone_storage_directory::{DirectoryCheckpointStore, DirectoryErrorV1, LimitsV1};
    use std::path::Path;

    pub type LocalExecutionStore = CheckpointExecutionStore<DirectoryCheckpointStore>;
    pub type LocalModelExecutionStore = CheckpointModelExecutionStore<DirectoryCheckpointStore>;
    pub type LocalAgentSessionStore = CheckpointAgentSessionStore<DirectoryCheckpointStore>;
    pub type LocalError = StoreErrorV1<DirectoryErrorV1>;

    pub fn create_new(
        path: impl AsRef<Path>,
        limits: StoreLimitsV1,
    ) -> Result<LocalExecutionStore, LocalError> {
        let backend = DirectoryCheckpointStore::create_new(path, mechanism_limits(limits))
            .map_err(StoreErrorV1::Backend)?;
        CheckpointExecutionStore::create(backend, limits)
    }

    pub fn open_existing(
        path: impl AsRef<Path>,
        limits: StoreLimitsV1,
    ) -> Result<LocalExecutionStore, LocalError> {
        let backend = DirectoryCheckpointStore::open_existing(path, mechanism_limits(limits))
            .map_err(StoreErrorV1::Backend)?;
        CheckpointExecutionStore::open_existing(backend, limits)
    }

    pub fn create_new_model(
        path: impl AsRef<Path>,
        limits: ModelStoreLimitsV1,
    ) -> Result<LocalModelExecutionStore, LocalError> {
        let backend = DirectoryCheckpointStore::create_new(path, model_mechanism_limits(limits))
            .map_err(StoreErrorV1::Backend)?;
        CheckpointModelExecutionStore::create(backend, limits)
    }

    pub fn open_existing_model(
        path: impl AsRef<Path>,
        limits: ModelStoreLimitsV1,
    ) -> Result<LocalModelExecutionStore, LocalError> {
        let backend = DirectoryCheckpointStore::open_existing(path, model_mechanism_limits(limits))
            .map_err(StoreErrorV1::Backend)?;
        CheckpointModelExecutionStore::open_existing(backend, limits)
    }

    pub fn create_new_agent(
        path: impl AsRef<Path>,
        limits: AgentStoreLimitsV1,
    ) -> Result<LocalAgentSessionStore, LocalError> {
        let backend = DirectoryCheckpointStore::create_new(path, agent_mechanism_limits(limits))
            .map_err(StoreErrorV1::Backend)?;
        CheckpointAgentSessionStore::create(backend, limits)
    }

    pub fn open_existing_agent(
        path: impl AsRef<Path>,
        limits: AgentStoreLimitsV1,
    ) -> Result<LocalAgentSessionStore, LocalError> {
        let backend = DirectoryCheckpointStore::open_existing(path, agent_mechanism_limits(limits))
            .map_err(StoreErrorV1::Backend)?;
        CheckpointAgentSessionStore::open_existing(backend, limits)
    }

    fn mechanism_limits(limits: StoreLimitsV1) -> LimitsV1 {
        LimitsV1 {
            max_key_bytes: 64,
            max_value_bytes: limits.max_bytes,
        }
    }

    fn model_mechanism_limits(limits: ModelStoreLimitsV1) -> LimitsV1 {
        LimitsV1 {
            max_key_bytes: 64,
            max_value_bytes: limits.max_bytes,
        }
    }

    fn agent_mechanism_limits(limits: AgentStoreLimitsV1) -> LimitsV1 {
        LimitsV1 {
            max_key_bytes: 64,
            max_value_bytes: limits.max_bytes,
        }
    }
}

#[cfg(unix)]
pub use unix::*;
