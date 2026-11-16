#![cfg(unix)]

use chronos_adapter_native::NativeRequest;
use chronos_engine::{Agent, CommandOutcomeV2, Engine, TaskSpecV2};
use chronos_host::{native::RequestV1, native::ResponseV1, worker::WorkerRequestV1};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    time::{Duration, SystemTime},
};

struct Allow;

impl chronos_service::Authorizer for Allow {
    fn allows(&mut self, _: &RequestV1) -> bool {
        true
    }
}

impl chronos_service::worker::WorkerAuthorizer for Allow {
    fn allows_worker(&mut self, _: &WorkerRequestV1) -> bool {
        true
    }

    fn allows_worker_result(&mut self, _: &WorkerRequestV1, _: &CommandOutcomeV2) -> bool {
        true
    }
}

fn limits() -> chronos_protocol::Limits {
    chronos_protocol::Limits {
        max_frame_bytes: 4_096,
        max_id_bytes: 64,
        max_graph_tasks: 4,
        max_dependencies_per_task: 4,
        max_capabilities_per_task: 4,
        max_capability_bytes: 64,
        max_page_entries: 4,
    }
}

fn main() {
    let socket = PathBuf::from(std::env::var_os("CHRONOS_CHAIN_SOCKET").expect("socket"));
    let mut service = running_service();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    BufReader::new(stream.try_clone().unwrap())
        .take((limits().max_frame_bytes + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .unwrap();
    assert_eq!(bytes.pop(), Some(b'\n'));
    let request = chronos_wire::decode_request(&bytes, limits()).unwrap();
    let native = request.native(limits()).unwrap();
    let response = chronos_adapter_native::response(service.dispatch(native));
    let encoded = chronos_wire::encode(&response, limits().max_frame_bytes).unwrap();
    stream.write_all(&encoded).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
    drop(stream);
    drop(listener);
    fs::remove_file(socket).unwrap();
}

fn running_service() -> chronos_service::Service<Allow> {
    let mut service = chronos_service::Service::new(
        Engine::new(),
        Allow,
        chronos_service::Limits {
            max_graph_tasks: 4,
            max_page_entries: 4,
        },
    );
    let Ok(ResponseV1::Revision(revision)) = service.dispatch(RequestV1::Revision) else {
        panic!("revision expected")
    };
    assert!(matches!(
        service.dispatch(RequestV1::SubmitGraph {
            expected: revision,
            tasks: vec![TaskSpecV2::new("moira-chain-task")],
        }),
        Ok(ResponseV1::SubmitGraph(Ok(())))
    ));
    let Ok(CommandOutcomeV2::AdvanceTime(Ok(time))) =
        service.dispatch_worker(WorkerRequestV1::AdvanceTime {
            now: SystemTime::UNIX_EPOCH,
        })
    else {
        panic!("time expected")
    };
    let Ok(CommandOutcomeV2::IssueGrant(Ok(grant))) =
        service.dispatch_worker(WorkerRequestV1::IssueGrant {
            agent: Agent::new("daimon-chain-worker"),
            time: time.clone(),
            validity_duration: Duration::from_secs(60),
            claim_budget: Some(1),
        })
    else {
        panic!("grant expected")
    };
    let Ok(ResponseV1::Revision(revision)) = service.dispatch(RequestV1::Revision) else {
        panic!("revision expected")
    };
    assert!(matches!(
        service.dispatch_worker(WorkerRequestV1::ClaimTask {
            expected: revision,
            grant,
            task_id: "moira-chain-task".into(),
            time,
            lease_duration: Duration::from_secs(30),
        }),
        Ok(CommandOutcomeV2::ClaimTask(Ok(_)))
    ));
    service
}
