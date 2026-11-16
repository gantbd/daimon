#![cfg(unix)]

use base64::Engine as _;
use daimon_process::{ProcessBoundaryErrorV1, ProcessBoundaryLaunchV1, ProcessBoundaryV1};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn spawn_boundary() -> (Child, ChildStdin, ChildStdout) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_daimon-process-boundary"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    (child, stdin, stdout)
}

fn write_frame(output: &mut impl Write, value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    output
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .unwrap();
    output.write_all(&bytes).unwrap();
    output.flush().unwrap();
}

fn read_frame(input: &mut impl Read) -> Value {
    let mut length = [0_u8; 4];
    input.read_exact(&mut length).unwrap();
    let mut bytes = vec![0_u8; u32::from_be_bytes(length) as usize];
    input.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn start_request(argv: Vec<String>, cwd: &str) -> Value {
    json!({
        "op": "start",
        "argv": argv,
        "cwd": cwd,
        "env": [],
        "env_clear": true
    })
}

#[test]
fn exact_argv_streams_bounded_pipe_output_and_reaps() {
    let (mut boundary, mut stdin, mut stdout) = spawn_boundary();
    write_frame(
        &mut stdin,
        &start_request(
            vec!["/usr/bin/printf".to_owned(), "hello".to_owned()],
            "/tmp",
        ),
    );
    let started = read_frame(&mut stdout);
    assert_eq!(started["event"], "started");
    let output = read_frame(&mut stdout);
    assert_eq!(output["event"], "output");
    assert_eq!(output["stream"], "stdout");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(output["data"].as_str().unwrap())
            .unwrap(),
        b"hello"
    );
    write_frame(&mut stdin, &json!({"op": "output_ack"}));
    let exited = read_frame(&mut stdout);
    assert_eq!(exited["event"], "exited");
    assert_eq!(exited["kind"], "exited");
    assert_eq!(exited["code"], 0);
    assert!(boundary.wait().unwrap().success());
}

#[test]
fn manager_preserves_utf8_suffix_and_observes_natural_exit() {
    let mut boundary = ProcessBoundaryV1::start(&ProcessBoundaryLaunchV1 {
        boundary_program: PathBuf::from(env!("CARGO_BIN_EXE_daimon-process-boundary")),
        argv: vec!["/usr/bin/printf".to_owned(), "ééé".to_owned()],
        cwd: PathBuf::from("/tmp"),
        environment: Vec::new(),
        output_byte_limit: 4,
        startup_timeout: Duration::from_secs(2),
        cancellation_timeout: Duration::from_secs(2),
    })
    .unwrap();
    assert!(!boundary.mechanism().is_empty());
    wait_until(Duration::from_secs(3), || {
        boundary.poll_exit().unwrap().is_some()
    });
    let output = boundary.output().unwrap();
    assert_eq!(output.output, "éé".as_bytes());
    assert!(output.truncated);
    assert_eq!(output.exit.unwrap().exit_code, Some(0));
}

#[test]
fn manager_cancellation_returns_only_after_the_group_is_reaped() {
    let mut boundary = ProcessBoundaryV1::start(&ProcessBoundaryLaunchV1 {
        boundary_program: PathBuf::from(env!("CARGO_BIN_EXE_daimon-process-boundary")),
        argv: vec!["/bin/sleep".to_owned(), "30".to_owned()],
        cwd: PathBuf::from("/tmp"),
        environment: Vec::new(),
        output_byte_limit: 64,
        startup_timeout: Duration::from_secs(2),
        cancellation_timeout: Duration::from_secs(3),
    })
    .unwrap();
    let exit = boundary.cancel().unwrap();
    assert!(exit.cancelled);
    assert_eq!(boundary.poll_exit().unwrap(), Some(exit));
}

#[test]
fn manager_refuses_relative_execution_and_redacts_launch_material() {
    let launch = ProcessBoundaryLaunchV1 {
        boundary_program: PathBuf::from(env!("CARGO_BIN_EXE_daimon-process-boundary")),
        argv: vec!["relative-command".to_owned(), "secret-argument".to_owned()],
        cwd: PathBuf::from("/tmp"),
        environment: vec![("SECRET_NAME".to_owned(), "secret-value".to_owned())],
        output_byte_limit: 64,
        startup_timeout: Duration::from_secs(2),
        cancellation_timeout: Duration::from_secs(2),
    };
    let debug = format!("{launch:?}");
    assert!(!debug.contains("secret-argument"));
    assert!(!debug.contains("SECRET_NAME"));
    assert!(!debug.contains("secret-value"));
    assert!(matches!(
        ProcessBoundaryV1::start(&launch),
        Err(ProcessBoundaryErrorV1::Invalid)
    ));
}

#[test]
fn owner_pipe_loss_kills_the_group_and_reaps_descendants() {
    let root = unique_path("owner-loss");
    fs::create_dir(&root).unwrap();
    let descendant_path = root.join("descendant.pid");
    let (mut boundary, mut stdin, mut stdout) = spawn_boundary();
    write_frame(
        &mut stdin,
        &start_request(
            vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "sleep 30 & echo $! > \"$1\"; wait".to_owned(),
                "daimon-boundary-test".to_owned(),
                descendant_path.to_str().unwrap().to_owned(),
            ],
            root.to_str().unwrap(),
        ),
    );
    let started = read_frame(&mut stdout);
    let direct_pid = u32::try_from(started["pid"].as_u64().unwrap()).unwrap();
    let direct_identity = processkit::process_info(direct_pid)
        .unwrap()
        .and_then(|info| info.start_time());
    wait_until(Duration::from_secs(3), || descendant_path.is_file());
    let descendant_pid = fs::read_to_string(&descendant_path)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    let descendant_identity = processkit::process_info(descendant_pid)
        .unwrap()
        .and_then(|info| info.start_time());

    drop(stdin);
    wait_until(Duration::from_secs(5), || {
        boundary.try_wait().unwrap().is_some()
    });
    wait_until(Duration::from_secs(3), || {
        !processkit::process_is_alive(direct_pid, direct_identity).unwrap()
            && !processkit::process_is_alive(descendant_pid, descendant_identity).unwrap()
    });
    assert!(!processkit::process_is_alive(direct_pid, direct_identity).unwrap());
    assert!(!processkit::process_is_alive(descendant_pid, descendant_identity).unwrap());
    fs::remove_dir_all(root).unwrap();
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !predicate() {
        assert!(Instant::now() < deadline, "condition did not settle");
        thread::sleep(Duration::from_millis(20));
    }
}

fn unique_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "daimon-process-boundary-{label}-{}-{nonce}",
        std::process::id()
    ))
}
