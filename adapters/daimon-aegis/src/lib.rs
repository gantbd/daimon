//! Current Daimon execution authorization through Aegis's public client.
//!
//! The Aegis grant handle remains session-local. Daimon receives only an opaque
//! host-bound context and fresh decision attribution; neither is bearer authority.

#![forbid(unsafe_code)]

use aegis_client::{AuthorityClient, ServicePort};
use aegis_protocol::{ActionV1, EngineNamespaceV1, GrantHandleV1, OutcomeV1, ReplyV1};
use daimon_host::{
    AuthenticatedSessionV1, AuthorityGrantV1, AuthorityRefusalV1, ExecutionAuthorizer,
};
use daimon_protocol::ExecuteRequestV1;

pub struct AegisAuthorizer<P> {
    authority: AuthorityClient<P>,
    grant: GrantHandleV1,
    principal: [u8; 16],
}

impl<P: ServicePort> AegisAuthorizer<P> {
    pub const fn new(
        authority: AuthorityClient<P>,
        grant: GrantHandleV1,
        principal: [u8; 16],
    ) -> Self {
        Self {
            authority,
            grant,
            principal,
        }
    }

    pub fn into_port(self) -> P {
        self.authority.into_port()
    }

    fn authorize_resource(
        &mut self,
        resource: [u8; 16],
        now: u64,
    ) -> Result<aegis_protocol::DecisionSummaryV1, AuthorityRefusalV1> {
        let reply = self
            .authority
            .authorize(
                self.grant,
                now,
                EngineNamespaceV1::Daimon,
                resource,
                ActionV1::Execute,
            )
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        match reply {
            ReplyV1::Accepted(OutcomeV1::Authorized(decision))
                if decision.engine == EngineNamespaceV1::Daimon
                    && decision.action == ActionV1::Execute
                    && decision.expires_at >= now =>
            {
                Ok(decision)
            }
            ReplyV1::Refused(aegis_protocol::RefusalV1::Expired) => {
                Err(AuthorityRefusalV1::Expired)
            }
            ReplyV1::Accepted(_) | ReplyV1::Refused(_) => Err(AuthorityRefusalV1::Denied),
        }
    }
}

impl<P: ServicePort> ExecutionAuthorizer for AegisAuthorizer<P> {
    fn authorize(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
        now: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
        if session.principal != self.principal
            || session.authority_context != grant_context(self.grant)
            || request.principal.into_bytes() != self.principal
        {
            return Err(AuthorityRefusalV1::Denied);
        }
        let profile = self.authorize_resource(request.profile.into_bytes(), now)?;
        let mut expires_at = profile.expires_at;
        let mut tools = request.tools.clone();
        tools.sort();
        tools.dedup();
        for tool in &tools {
            let decision = self.authorize_resource(tool.into_bytes(), now)?;
            expires_at = expires_at.min(decision.expires_at);
        }
        Ok(AuthorityGrantV1 {
            decision_id: decision_id(profile.handle.0),
            expires_at,
            tools,
        })
    }
}

/// Stable opaque binding between a Daimon service session and one Aegis grant
/// handle. The bytes are correlation only and Aegis still validates the handle.
pub const fn grant_context(grant: GrantHandleV1) -> [u8; 16] {
    let id = grant.0.to_be_bytes();
    [
        b'D', b'A', b'I', b'M', b'G', b'R', b'N', b'1', id[0], id[1], id[2], id[3], id[4], id[5],
        id[6], id[7],
    ]
}

fn decision_id(handle: u64) -> [u8; 16] {
    let id = handle.to_be_bytes();
    [
        b'A', b'E', b'G', b'I', b'S', b'D', b'0', b'1', id[0], id[1], id[2], id[3], id[4], id[5],
        id[6], id[7],
    ]
}
