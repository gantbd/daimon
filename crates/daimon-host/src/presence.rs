//! Ephemeral observations supplied by the Daimon host's supervisor.

use crate::AuthenticatedSessionV1;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub type AgentId = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Observed { age: Duration },
    Stale { age: Duration },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Entry {
    pub agent: AgentId,
    pub observation: Observation,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Page {
    pub entries: Vec<Entry>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    Denied,
    Unavailable,
    InvalidLimit,
}

/// The host checks current roster and individual agent disclosure rights.
pub trait Disclosure {
    fn allows_roster(&mut self, session: &AuthenticatedSessionV1) -> bool;
    fn allows_agent(&mut self, session: &AuthenticatedSessionV1, agent: AgentId) -> bool;
}

/// One roster per supervisor scope. The supervisor owns membership and time.
/// After restart the roster starts unavailable until the supervisor reports
/// an authoritative snapshot, which may be empty.
pub struct Roster {
    observations: Option<BTreeMap<AgentId, Instant>>,
    capacity: usize,
    freshness: Duration,
}

impl Roster {
    pub fn new(capacity: usize, freshness: Duration) -> Self {
        Self {
            observations: None,
            capacity,
            freshness,
        }
    }

    /// Replace the live roster after the supervisor completes a bounded census.
    /// A failed census invalidates the prior view.
    pub fn replace(&mut self, observations: impl IntoIterator<Item = (AgentId, Instant)>) -> bool {
        let mut next = BTreeMap::new();
        for (agent, observed_at) in observations {
            if next.len() == self.capacity || next.insert(agent, observed_at).is_some() {
                self.mark_unavailable();
                return false;
            }
        }
        self.observations = Some(next);
        true
    }

    pub fn mark_unavailable(&mut self) {
        self.observations = None;
    }

    pub fn read(
        &self,
        session: &AuthenticatedSessionV1,
        disclosure: &mut impl Disclosure,
        now: Instant,
        limit: usize,
    ) -> Result<Page, ReadError> {
        if !disclosure.allows_roster(session) {
            return Err(ReadError::Denied);
        }
        if !(1..=usize::from(daimon_protocol::MAX_PRESENCE_ENTRIES)).contains(&limit) {
            return Err(ReadError::InvalidLimit);
        }
        let observations = self.observations.as_ref().ok_or(ReadError::Unavailable)?;
        let mut entries = Vec::new();
        for (&agent, &observed_at) in observations {
            if !disclosure.allows_agent(session, agent) {
                continue;
            }
            let age = now
                .checked_duration_since(observed_at)
                .ok_or(ReadError::Unavailable)?;
            if entries.len() == limit {
                return Ok(Page {
                    entries,
                    truncated: true,
                });
            }
            let observation = if age < self.freshness {
                Observation::Observed { age }
            } else {
                Observation::Stale { age }
            };
            entries.push(Entry { agent, observation });
        }
        Ok(Page {
            entries,
            truncated: false,
        })
    }
}
