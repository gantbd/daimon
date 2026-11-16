#![cfg(unix)]

use daimon_client::ExecutionClient;
use daimon_harness::Limits;
use daimon_host::{
    AttemptRefusalV1, AttemptValidator, AuthenticatedSessionV1, AuthorityGrantV1,
    AuthorityRefusalV1, ExecutionAuthorizer, Provider, ProviderOutcomeV1, ProviderReceiptV1,
};
use daimon_local_daemon::unix::{Authenticator, Daemon, connect};
use daimon_protocol::{
    CommandV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionDispositionV1, ExecutionIdV1,
    HarnessProfileIdV1, IdempotencyKeyV1, OutcomeV1, PrincipalIdV1, ReplyV1, TaskAttemptRefV1,
    ToolCapabilityIdV1,
};
use daimon_service::{Service, ServiceLimitsV1};
use daimon_wire::{LimitsV1, RequestFrameV1, decode_session_opened, encode_request};
use std::{
    convert::Infallible,
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

struct Authentication;
impl Authenticator for Authentication {
    type Error = Infallible;

    fn authenticate(&mut self, _: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error> {
        Ok(AuthenticatedSessionV1 {
            principal: [4; 16],
            authority_context: [9; 16],
        })
    }
}

struct Authorizer;
impl ExecutionAuthorizer for Authorizer {
    fn authorize(
        &mut self,
        _: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
        _: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1> {
        Ok(AuthorityGrantV1 {
            decision_id: [8; 16],
            expires_at: 20,
            tools: request.tools.clone(),
        })
    }
}

struct Attempts;
impl AttemptValidator for Attempts {
    fn validate(
        &mut self,
        _: &AuthenticatedSessionV1,
        _: &ExecuteRequestV1,
    ) -> Result<(), AttemptRefusalV1> {
        Ok(())
    }
}

struct FakeProvider(Arc<AtomicUsize>);
impl Provider for FakeProvider {
    fn execute(&mut self, request: &ExecuteRequestV1) -> ProviderOutcomeV1 {
        self.0.fetch_add(1, Ordering::SeqCst);
        ProviderOutcomeV1::Receipt(ProviderReceiptV1 {
            execution_id: request.execution_id,
            disposition: ExecutionDispositionV1::Completed,
            output_bytes: 12,
            artifacts: vec![],
        })
    }
}

struct ProcessProvider(PathBuf);
impl Provider for ProcessProvider {
    fn execute(&mut self, request: &ExecuteRequestV1) -> ProviderOutcomeV1 {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.0)
            .expect("provider must not be dispatched twice across restart");
        ProviderOutcomeV1::Receipt(ProviderReceiptV1 {
            execution_id: request.execution_id,
            disposition: ExecutionDispositionV1::Completed,
            output_bytes: 12,
            artifacts: vec![],
        })
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "daimon-daemon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn store(&self) -> PathBuf {
        self.0.join("execution")
    }

    fn socket(&self) -> PathBuf {
        self.0.join("daemon.sock")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn request() -> ExecuteRequestV1 {
    ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new([1; 16]),
        task_attempt: TaskAttemptRefV1 {
            task_key: [2; 16],
            task_incarnation: 3,
            attempt_number: 1,
        },
        principal: PrincipalIdV1::new([4; 16]),
        profile: HarnessProfileIdV1::new([5; 16]),
        idempotency_key: IdempotencyKeyV1::new([6; 16]),
        context: vec![],
        tools: vec![ToolCapabilityIdV1::new([7; 16])],
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 1,
            max_context_bytes: 1_024,
            max_output_bytes: 1_024,
        },
    }
}

fn store_limits() -> daimon_checkpoint::StoreLimitsV1 {
    daimon_checkpoint::StoreLimitsV1 {
        max_bytes: 16_384,
        max_executions: 4,
        max_context_references: 4,
        max_tools: 4,
        max_artifacts: 4,
    }
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket was not published");
}

fn spawn_daemon(mode: &str, fixture: &Fixture) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("process_daemon_helper")
        .arg("--exact")
        .arg("--nocapture")
        .env("DAIMON_DAEMON_HELPER", "1")
        .env("DAIMON_DAEMON_MODE", mode)
        .env("DAIMON_DAEMON_STORE", fixture.store())
        .env("DAIMON_DAEMON_SOCKET", fixture.socket())
        .env("DAIMON_PROVIDER_MARKER", fixture.0.join("provider-called"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn process_daemon_helper() {
    if std::env::var_os("DAIMON_DAEMON_HELPER").is_none() {
        return;
    }
    let store_path = PathBuf::from(std::env::var_os("DAIMON_DAEMON_STORE").unwrap());
    let socket_path = PathBuf::from(std::env::var_os("DAIMON_DAEMON_SOCKET").unwrap());
    let provider_marker = PathBuf::from(std::env::var_os("DAIMON_PROVIDER_MARKER").unwrap());
    let store = match std::env::var("DAIMON_DAEMON_MODE").unwrap().as_str() {
        "create" => daimon_local::create_new(store_path, store_limits()).unwrap(),
        "open" => daimon_local::open_existing(store_path, store_limits()).unwrap(),
        mode => panic!("unknown daemon helper mode {mode}"),
    };
    let service = Service::open(
        Limits::default(),
        ServiceLimitsV1 {
            max_sessions: 4,
            max_executions: 4,
        },
        Authorizer,
        Attempts,
        ProcessProvider(provider_marker),
        store,
    )
    .unwrap();
    let mut daemon = Daemon::bind_new(
        socket_path,
        service,
        Authentication,
        LimitsV1::default(),
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    let _ = daemon.serve_next();
}

fn service(
    store: daimon_local::LocalExecutionStore,
    calls: Arc<AtomicUsize>,
) -> Service<Authorizer, Attempts, FakeProvider, daimon_local::LocalExecutionStore> {
    Service::open(
        Limits::default(),
        ServiceLimitsV1 {
            max_sessions: 4,
            max_executions: 4,
        },
        Authorizer,
        Attempts,
        FakeProvider(calls),
        store,
    )
    .unwrap()
}

#[test]
fn real_private_socket_reopens_exact_result_without_provider_redispatch() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let store = daimon_local::create_new(fixture.store(), store_limits()).unwrap();
    let mut daemon = Daemon::bind_new(
        fixture.socket(),
        service(store, calls.clone()),
        Authentication,
        LimitsV1::default(),
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(fixture.socket()).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let socket = fixture.socket();
    let first_request = request();
    let client = thread::spawn(move || {
        let (session, port) = connect(socket, LimitsV1::default(), Duration::from_secs(2)).unwrap();
        ExecutionClient::new(session, port)
            .execute(first_request, 10)
            .unwrap()
    });
    daemon.serve_next().unwrap();
    let first = client.join().unwrap();
    assert!(matches!(first, ReplyV1::Accepted(OutcomeV1::Executed(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(daemon.health().accepted_connections, 1);
    drop(daemon);
    assert!(!fixture.socket().exists());

    let store = daimon_local::open_existing(fixture.store(), store_limits()).unwrap();
    let mut daemon = Daemon::bind_new(
        fixture.socket(),
        service(store, calls.clone()),
        Authentication,
        LimitsV1::default(),
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    let socket = fixture.socket();
    let second_request = request();
    let client = thread::spawn(move || {
        let (session, port) = connect(socket, LimitsV1::default(), Duration::from_secs(2)).unwrap();
        ExecutionClient::new(session, port)
            .execute(second_request, 11)
            .unwrap()
    });
    daemon.serve_next().unwrap();
    assert_eq!(client.join().unwrap(), first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(daemon);
    assert!(!fixture.socket().exists());
}

#[test]
fn process_exit_reopen_reconciles_discarded_reply_without_provider_redispatch() {
    let fixture = Fixture::new();
    let first = spawn_daemon("create", &fixture);
    wait_for_socket(&fixture.socket());

    let mut stream = UnixStream::connect(fixture.socket()).unwrap();
    let session = decode_session_opened(&read_frame(&mut stream), LimitsV1::default()).unwrap();
    let bytes = encode_request(
        &RequestFrameV1 {
            session,
            command: CommandV1::Execute {
                request: request(),
                now: 10,
            },
        },
        LimitsV1::default(),
    )
    .unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    // The client transmitted the request but intentionally retains no reply.
    drop(stream);

    let first_output = first.wait_with_output().unwrap();
    assert!(
        first_output.status.success(),
        "first daemon failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    assert!(fixture.0.join("provider-called").exists());
    assert!(!fixture.socket().exists());

    let second = spawn_daemon("open", &fixture);
    wait_for_socket(&fixture.socket());
    let (session, port) = connect(
        fixture.socket(),
        LimitsV1::default(),
        Duration::from_secs(2),
    )
    .unwrap();
    let reply = ExecutionClient::new(session, port)
        .execute(request(), 11)
        .unwrap();
    assert!(matches!(reply, ReplyV1::Accepted(OutcomeV1::Executed(_))));

    let second_output = second.wait_with_output().unwrap();
    assert!(
        second_output.status.success(),
        "second daemon failed: {}",
        String::from_utf8_lossy(&second_output.stderr)
    );
    assert!(!fixture.socket().exists());
}

#[test]
fn roster_reads_use_authenticated_disclosure_without_dispatching_provider() {
    use daimon_client::ReadOnlyClient;
    use daimon_host::presence::{AgentId, Disclosure, Roster};
    use daimon_protocol::RefusalV1;
    use std::{sync::RwLock, time::Instant};

    struct Policy;
    impl Disclosure for Policy {
        fn allows_roster(&mut self, session: &AuthenticatedSessionV1) -> bool {
            session.principal == [4; 16]
        }
        fn allows_agent(&mut self, _: &AuthenticatedSessionV1, agent: AgentId) -> bool {
            agent == [1; 16]
        }
    }

    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let store = daimon_local::create_new(fixture.store(), store_limits()).unwrap();
    let timeout = Duration::from_secs(2);
    let mut daemon = Daemon::bind_new(
        fixture.socket(),
        service(store, calls.clone()),
        Authentication,
        LimitsV1::default(),
        timeout,
        3,
    )
    .unwrap();
    let roster = Arc::new(RwLock::new(Roster::new(2, timeout)));
    daemon.bind_presence(roster.clone(), Policy);
    let socket = fixture.socket();
    let client = thread::spawn(move || {
        let (session, port) = connect(socket, LimitsV1::default(), timeout).unwrap();
        let mut client = ReadOnlyClient::new(session, port);
        assert_eq!(
            client.read_presence(1).unwrap(),
            ReplyV1::Refused(RefusalV1::PresenceUnavailable)
        );
        let now = Instant::now();
        assert!(
            roster
                .write()
                .unwrap()
                .replace([([1; 16], now - timeout), ([2; 16], now)])
        );
        let ReplyV1::Accepted(OutcomeV1::Presence { entries, truncated }) =
            client.read_presence(1).unwrap()
        else {
            panic!("expected roster")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].agent, [1; 16]);
        assert!(entries[0].stale);
        assert!(!truncated);
        roster.write().unwrap().replace([]);
        assert_eq!(
            client.read_presence(16).unwrap(),
            ReplyV1::Accepted(OutcomeV1::Presence {
                entries: vec![],
                truncated: false,
            })
        );
    });
    daemon.serve_next().unwrap();
    client.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn local_supervisor_reports_owned_child_then_reaps_on_exit() {
    use daimon_host::presence::{AgentId, Disclosure};
    use daimon_local_daemon::supervisor::LocalSupervisor;
    use std::io::Write as _;
    use std::sync::Mutex;

    struct Policy;
    impl Disclosure for Policy {
        fn allows_roster(&mut self, _: &AuthenticatedSessionV1) -> bool {
            true
        }
        fn allows_agent(&mut self, _: &AuthenticatedSessionV1, _: AgentId) -> bool {
            true
        }
    }

    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let store = daimon_local::create_new(fixture.store(), store_limits()).unwrap();
    let timeout = Duration::from_secs(2);
    let mut daemon = Daemon::bind_new(
        fixture.socket(),
        service(store, calls.clone()),
        Authentication,
        LimitsV1::default(),
        timeout,
        64,
    )
    .unwrap();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "read -r line"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut supervisor = LocalSupervisor::new(1);
    supervisor.register([1; 16], child).unwrap();
    daemon.bind_local_supervisor(Arc::new(Mutex::new(supervisor)), 1, timeout, Policy);

    let socket = fixture.socket();
    let client = thread::spawn(move || {
        let (session, port) = connect(socket, LimitsV1::default(), timeout).unwrap();
        let mut client = daimon_client::ReadOnlyClient::new(session, port);
        let ReplyV1::Accepted(OutcomeV1::Presence {
            entries,
            truncated: false,
        }) = client.read_presence(16).unwrap()
        else {
            panic!("expected supervised child")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].agent, [1; 16]);
        assert!(!entries[0].stale);
        writeln!(input, "exit").unwrap();
        for _ in 0..50 {
            let ReplyV1::Accepted(OutcomeV1::Presence { entries, .. }) =
                client.read_presence(16).unwrap()
            else {
                panic!("expected roster")
            };
            if entries.is_empty() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("supervised child did not exit");
    });
    daemon.serve_next().unwrap();
    client.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
