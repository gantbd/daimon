#![forbid(unsafe_code)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: qualification_chronos SOCKET [TASK]")?,
    );
    let expected_task = arguments
        .next()
        .map(|value| value.into_string().map_err(|_| "task must be UTF-8"))
        .transpose()?
        .unwrap_or_else(|| "local-agent-task".to_owned());
    if arguments.next().is_some() {
        return Err("usage: qualification_chronos SOCKET [TASK]".into());
    }
    let listener = UnixListener::bind(socket)?;
    let limits = limits();
    let (mut stream, _) = listener.accept()?;
    let mut request = Vec::new();
    BufReader::new(stream.try_clone()?)
        .take((limits.max_frame_bytes + 1) as u64)
        .read_until(b'\n', &mut request)?;
    if request.pop() != Some(b'\n') {
        return Err("Chronos qualification request was not newline framed".into());
    }
    let request = chronos_wire::decode_request(&request, limits)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    if !matches!(
        request.command,
        chronos_protocol::Command::Snapshot { ref task } if task == &expected_task
    ) {
        return Err("Chronos qualification received an unexpected command".into());
    }
    let response = chronos_protocol::Response {
        version: 1,
        outcome: chronos_protocol::Outcome::Snapshot {
            value: Some(chronos_protocol::Entry {
                reference: chronos_protocol::Reference {
                    task: expected_task.clone(),
                    incarnation: "1".to_owned(),
                },
                snapshot: chronos_protocol::Snapshot {
                    phase: chronos_protocol::Phase::Running,
                    attempt_number: Some(1),
                    dependency_count: 0,
                    required_capability_count: 0,
                    priority: 0,
                    max_attempts: 1,
                },
            }),
            revision: Some(chronos_protocol::Revision::Finite("1".to_owned())),
        },
    };
    let response = chronos_wire::encode(&response, limits.max_frame_bytes)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    stream.write_all(&response)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn limits() -> chronos_protocol::Limits {
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
