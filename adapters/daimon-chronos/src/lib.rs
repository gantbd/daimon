//! Current exact-attempt validation through Chronos's public observation client.
//!
//! Daimon task keys are deployment identities, not Chronos task names or leases.
//! The explicit bounded registry is the sole mapping between those namespaces.

#![forbid(unsafe_code)]

use chronos_client::WireClientV1;
use chronos_protocol as chronos;
use daimon_host::{AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1};
use daimon_protocol::ExecuteRequestV1;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskBindingV1 {
    pub external_task_key: [u8; 16],
    pub chronos_task_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationErrorV1 {
    InvalidLimits,
    EmptyRegistry,
    RegistryLimit,
    InvalidTaskId,
    DuplicateExternalKey,
    DuplicateTaskId,
}

pub struct ChronosAttemptValidator<P> {
    port: P,
    limits: chronos::Limits,
    tasks: BTreeMap<[u8; 16], String>,
}

impl<P> ChronosAttemptValidator<P> {
    pub fn new(
        port: P,
        limits: chronos::Limits,
        max_bindings: usize,
        bindings: Vec<TaskBindingV1>,
    ) -> Result<Self, ConfigurationErrorV1> {
        if max_bindings == 0 || limits.max_frame_bytes == 0 || limits.max_id_bytes == 0 {
            return Err(ConfigurationErrorV1::InvalidLimits);
        }
        if bindings.is_empty() {
            return Err(ConfigurationErrorV1::EmptyRegistry);
        }
        if bindings.len() > max_bindings {
            return Err(ConfigurationErrorV1::RegistryLimit);
        }
        let mut tasks = BTreeMap::new();
        let mut names = BTreeSet::new();
        for binding in bindings {
            if binding.chronos_task_id.is_empty()
                || binding.chronos_task_id.len() > limits.max_id_bytes
            {
                return Err(ConfigurationErrorV1::InvalidTaskId);
            }
            if !names.insert(binding.chronos_task_id.clone()) {
                return Err(ConfigurationErrorV1::DuplicateTaskId);
            }
            if tasks
                .insert(binding.external_task_key, binding.chronos_task_id)
                .is_some()
            {
                return Err(ConfigurationErrorV1::DuplicateExternalKey);
            }
        }
        Ok(Self {
            port,
            limits,
            tasks,
        })
    }

    pub fn into_port(self) -> P {
        self.port
    }
}

impl<P: WireClientV1> AttemptValidator for ChronosAttemptValidator<P> {
    fn validate(
        &mut self,
        _: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
    ) -> Result<(), AttemptRefusalV1> {
        let Some(task_id) = self.tasks.get(&request.task_attempt.task_key) else {
            return Err(AttemptRefusalV1::NotCurrent);
        };
        let command = chronos::Request {
            version: 1,
            command: chronos::Command::Snapshot {
                task: task_id.clone(),
            },
        };
        command
            .validate(self.limits)
            .map_err(|_| AttemptRefusalV1::Unavailable)?;
        let response = self
            .port
            .request(command)
            .map_err(|_| AttemptRefusalV1::Unavailable)?;
        response
            .validate(self.limits.max_id_bytes)
            .map_err(|_| AttemptRefusalV1::Unavailable)?;
        let chronos::Outcome::Snapshot {
            value: Some(entry),
            revision: Some(_),
        } = response.outcome
        else {
            return Err(AttemptRefusalV1::NotCurrent);
        };
        let incarnation =
            decimal(&entry.reference.incarnation).ok_or(AttemptRefusalV1::Unavailable)?;
        if entry.reference.task != *task_id
            || incarnation != request.task_attempt.task_incarnation
            || !matches!(entry.snapshot.phase, chronos::Phase::Running)
            || entry.snapshot.attempt_number != Some(request.task_attempt.attempt_number)
        {
            return Err(AttemptRefusalV1::NotCurrent);
        }
        Ok(())
    }
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}
