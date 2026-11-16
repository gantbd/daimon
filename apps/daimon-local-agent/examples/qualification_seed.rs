#![forbid(unsafe_code)]

use daimon_client::AgentSessionClient;
use daimon_protocol::{self as protocol, agent::*};
use std::{path::PathBuf, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = PathBuf::from(arguments.next().ok_or("usage: qualification_seed SOCKET")?);
    if arguments.next().is_some() {
        return Err("usage: qualification_seed SOCKET".into());
    }
    let (service_session, port) = daimon_client::unix::connect_agent(
        socket,
        daimon_wire::LimitsV1::default(),
        daimon_wire::agent::AgentWireLimitsV1::default(),
        Duration::from_secs(3),
    )
    .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let mut client = AgentSessionClient::new(service_session, port);
    let reply = client
        .open(
            AgentOpenRequestV1 {
                session: protocol::AgentSessionIdV1::new([7; 16]),
                execution: protocol::ExecuteRequestV1 {
                    execution_id: protocol::ExecutionIdV1::new([12; 16]),
                    task_attempt: protocol::TaskAttemptRefV1 {
                        task_key: [13; 16],
                        task_incarnation: 1,
                        attempt_number: 1,
                    },
                    principal: protocol::PrincipalIdV1::new([2; 16]),
                    profile: protocol::HarnessProfileIdV1::new([3; 16]),
                    idempotency_key: protocol::IdempotencyKeyV1::new([14; 16]),
                    context: Vec::new(),
                    tools: Vec::new(),
                    budget: protocol::ExecutionBudgetV1 {
                        max_elapsed_millis: 5_000,
                        max_input_tokens: 100,
                        max_output_tokens: 100,
                        max_tool_calls: 1,
                        max_context_bytes: 4_096,
                        max_output_bytes: 4_096,
                    },
                },
                workspace: [6; 16],
                budget: AgentSessionBudgetV1 {
                    max_elapsed_millis: 10_000,
                    max_turns: 2,
                    max_events: 32,
                    max_event_bytes: 4_096,
                    max_prompt_bytes: 4_096,
                    max_permission_requests: 0,
                },
            },
            10,
        )
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)) = reply else {
        return Err(format!("qualification session open refused: {reply:?}").into());
    };
    if view.phase != AgentSessionPhaseV1::Ready || !view.capabilities.resume_session {
        return Err("qualification session did not retain resumable ready state".into());
    }
    println!("{}", view.revision);
    Ok(())
}
