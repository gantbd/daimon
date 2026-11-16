//! Presence for child processes handed to the Daimon host at launch.
use daimon_host::presence::{AgentId, Roster};
use std::{collections::BTreeMap, io, process::Child, time::Instant};

/// Owns wait handles for one local supervisor scope. Callers launch agents
/// through their existing authorized provider and transfer their child handle.
pub struct LocalSupervisor {
    children: BTreeMap<AgentId, Child>,
    capacity: usize,
}

impl LocalSupervisor {
    pub fn new(capacity: usize) -> Self {
        Self {
            children: BTreeMap::new(),
            capacity,
        }
    }

    /// On refusal return the handle to the caller so it can still reap it.
    pub fn register(&mut self, agent: AgentId, child: Child) -> Result<(), Child> {
        if self.children.len() == self.capacity || self.children.contains_key(&agent) {
            return Err(child);
        }
        self.children.insert(agent, child);
        Ok(())
    }

    /// Reap exited children and publish a fresh observation of each remaining
    /// child. A wait failure invalidates the whole census until another read.
    pub fn refresh(&mut self, roster: &mut Roster) -> io::Result<()> {
        let mut observations = Vec::with_capacity(self.children.len());
        let mut error = None;
        self.children.retain(|agent, child| match child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => {
                observations.push((*agent, Instant::now()));
                true
            }
            Err(failure) => {
                error = Some(failure);
                true
            }
        });
        if let Some(error) = error {
            roster.mark_unavailable();
            return Err(error);
        }
        if !roster.replace(observations) {
            return Err(io::Error::other(
                "supervisor census exceeds roster capacity",
            ));
        }
        Ok(())
    }
}
