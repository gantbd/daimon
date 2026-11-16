//! Bounded routing across distinct interactive-agent provider transports.
//!
//! Routing is selected only by a host-registered frozen profile document
//! digest. A session route is retained before the first provider admission so
//! an ambiguous open can never fall through to another backend.

#![forbid(unsafe_code)]

use daimon_host::agent::{
    AgentProfileResolver, AgentProvider, AgentProviderInvocationV1, AgentProviderOutcomeV1,
};
use daimon_host::{AuthenticatedSessionV1, ProfileRefusalV1};
use daimon_protocol::agent::{AgentOpenRequestV1, AgentProfileSnapshotV1};
use daimon_protocol::{AgentSessionIdV1, ContentDigestV1, HarnessProfileIdV1};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRouterConfigurationErrorV1 {
    InvalidLimits,
    EmptyRoute,
    DuplicateProfile,
}

pub struct AgentProviderRouteV1 {
    pub profile_documents: Vec<ContentDigestV1>,
    pub provider: Box<dyn AgentProvider>,
}

/// Routes a bounded number of sessions to statically registered providers.
///
/// Entries are intentionally not removed on close. Daimon's service owns
/// idempotent replay, while retaining the route prevents a reused session
/// identity from reaching a different provider in the same process lifetime.
pub struct AgentProviderRouter {
    max_sessions: usize,
    routes: Vec<Box<dyn AgentProvider>>,
    profiles: BTreeMap<ContentDigestV1, usize>,
    sessions: BTreeMap<AgentSessionIdV1, usize>,
}

impl AgentProviderRouter {
    pub fn try_new(
        max_sessions: usize,
        registrations: Vec<AgentProviderRouteV1>,
    ) -> Result<Self, AgentRouterConfigurationErrorV1> {
        if max_sessions == 0 || registrations.is_empty() {
            return Err(AgentRouterConfigurationErrorV1::InvalidLimits);
        }
        let mut routes = Vec::new();
        let mut profiles = BTreeMap::new();
        for registration in registrations {
            if registration.profile_documents.is_empty() {
                return Err(AgentRouterConfigurationErrorV1::EmptyRoute);
            }
            let route = routes.len();
            for profile in registration.profile_documents {
                if profiles.insert(profile, route).is_some() {
                    return Err(AgentRouterConfigurationErrorV1::DuplicateProfile);
                }
            }
            routes.push(registration.provider);
        }
        Ok(Self {
            max_sessions,
            routes,
            profiles,
            sessions: BTreeMap::new(),
        })
    }

    fn route_for_session(&self, session: AgentSessionIdV1) -> Option<usize> {
        self.sessions.get(&session).copied()
    }
}

impl AgentProvider for AgentProviderRouter {
    fn invoke_agent(&mut self, invocation: &AgentProviderInvocationV1) -> AgentProviderOutcomeV1 {
        let route = match invocation {
            AgentProviderInvocationV1::Open {
                request, profile, ..
            } => {
                if self.sessions.contains_key(&request.session)
                    || self.sessions.len() >= self.max_sessions
                {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                }
                let Some(route) = self.profiles.get(&profile.document_digest).copied() else {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                };
                // Fence before provider admission. Even OutcomeUnknown remains
                // bound to this backend and cannot fall through to another.
                self.sessions.insert(request.session, route);
                route
            }
            AgentProviderInvocationV1::Prompt {
                request, profile, ..
            } => {
                let Some(route) = self.route_for_session(request.session) else {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                };
                if self.profiles.get(&profile.document_digest).copied() != Some(route) {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                }
                route
            }
            AgentProviderInvocationV1::Reattach {
                session, profile, ..
            } => {
                let Some(route) = self.profiles.get(&profile.document_digest).copied() else {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                };
                if let Some(existing) = self.route_for_session(*session) {
                    if existing != route {
                        return AgentProviderOutcomeV1::OutcomeUnknown;
                    }
                } else if self.sessions.len() >= self.max_sessions {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                } else {
                    // Recovery is explicitly profile-selected and fenced before
                    // the provider is invoked, just like a first open.
                    self.sessions.insert(*session, route);
                }
                route
            }
            AgentProviderInvocationV1::DecidePermission { session, .. }
            | AgentProviderInvocationV1::Advance { session, .. }
            | AgentProviderInvocationV1::Cancel { session, .. }
            | AgentProviderInvocationV1::Close { session, .. } => {
                let Some(route) = self.route_for_session(*session) else {
                    return AgentProviderOutcomeV1::OutcomeUnknown;
                };
                route
            }
        };
        self.routes[route].invoke_agent(invocation)
    }
}

/// Frozen profile resolver shared by mixed-provider service composition.
#[derive(Clone)]
pub struct StaticAgentProfileRouter {
    profiles: BTreeMap<HarnessProfileIdV1, AgentProfileSnapshotV1>,
}

impl StaticAgentProfileRouter {
    pub fn try_new(
        max_profiles: usize,
        profiles: Vec<AgentProfileSnapshotV1>,
    ) -> Result<Self, AgentRouterConfigurationErrorV1> {
        if max_profiles == 0 || profiles.is_empty() || profiles.len() > max_profiles {
            return Err(AgentRouterConfigurationErrorV1::InvalidLimits);
        }
        let mut values = BTreeMap::new();
        let mut documents = BTreeMap::new();
        for profile in profiles {
            if documents.insert(profile.document_digest, ()).is_some()
                || values.insert(profile.harness_profile, profile).is_some()
            {
                return Err(AgentRouterConfigurationErrorV1::DuplicateProfile);
            }
        }
        Ok(Self { profiles: values })
    }
}

impl AgentProfileResolver for StaticAgentProfileRouter {
    fn resolve_agent_profile(
        &mut self,
        _service_session: &AuthenticatedSessionV1,
        request: &AgentOpenRequestV1,
    ) -> Result<AgentProfileSnapshotV1, ProfileRefusalV1> {
        self.profiles
            .get(&request.execution.profile)
            .cloned()
            .ok_or(ProfileRefusalV1::Unknown)
    }
}
