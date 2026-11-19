#![cfg(unix)]

use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
};

fn read_request(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        request.extend_from_slice(&buffer[..count]);
        if let Some(index) = request.windows(4).position(|value| value == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header = std::str::from_utf8(&request[..header_end]).unwrap();
    let content_length = header
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    while request.len() < header_end + content_length {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        request.extend_from_slice(&buffer[..count]);
    }
}

#[test]
fn owner_retains_one_completion_qualification_and_replay_never_redispatches() {
    let root =
        std::env::temp_dir().join(format!("daimon-model-qualification-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        sent.send(()).unwrap();
        let body = serde_json::to_vec(&json!({
            "choices": [{"message": {"content": "qualification answer"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 9, "completion_tokens": 3}
        }))
        .unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    });

    let config = root.join("model.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&json!({
            "principal": "01010101010101010101010101010101",
            "aegis_socket": root.join("aegis.sock"),
            "aegis_expected_epoch": 0,
            "aegis_grant_now": 1,
            "aegis_grant_expires_at": 1000,
            "chronos_socket": root.join("chronos.sock"),
            "daimon_socket": root.join("model.sock"),
            "store_directory": root.join("store"),
            "provider": {
                "provider_id": "02020202020202020202020202020202",
                "harness_profile_id": "03030303030303030303030303030303",
                "model": "qualified-local-model",
                "address": address.to_string(),
                "host_header": address.to_string(),
                "path": "/v1/chat/completions",
                "structured_output": false,
                "structured_tools": true,
                "sampling_temperature_milli": 0,
                "connect_timeout_ms": 1000,
                "io_timeout_ms": 1000,
                "max_request_bytes": 65536,
                "max_response_bytes": 65536
            },
            "task_bindings": [{
                "external_task_key": "04040404040404040404040404040404",
                "chronos_task_id": "qualification-task"
            }],
            "context": [{
                "reference": "05050505050505050505050505050505",
                "kind": "chronos_work",
                "text": "bounded work"
            }],
            "messages": [{"role": "system", "content": "answer carefully"}],
            "io_timeout_ms": 1000,
            "max_executions": 8,
            "max_requests_per_connection": 4
        }))
        .unwrap(),
    )
    .unwrap();

    let executable = env!("CARGO_BIN_EXE_daimon-local-model");
    let catalogue = Command::new(executable)
        .arg("--describe-providers")
        .arg(&config)
        .output()
        .unwrap();
    assert!(catalogue.status.success());
    let catalogue: serde_json::Value = serde_json::from_slice(&catalogue.stdout).unwrap();
    let request = serde_json::to_vec(&json!({
        "version": 1,
        "operation_id": "06060606060606060606060606060606",
        "expected_document_digest": catalogue["document_digest"]
    }))
    .unwrap();

    let invoke = || {
        let mut child = Command::new(executable)
            .arg("--qualify-provider")
            .arg(&config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&request).unwrap();
        child.wait_with_output().unwrap()
    };
    let first = invoke();
    assert!(first.status.success(), "{:?}", first.stderr);
    received.recv().unwrap();
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["disposition"], "qualified_completion");
    assert_eq!(first["completion"], true);
    assert_eq!(first["tool_continuation"], "not_exercised");
    assert_eq!(first["input_tokens"], 9);
    assert_eq!(first["output_tokens"], 3);
    assert_eq!(first["output_bytes"], 20);
    assert_eq!(first["replayed"], false);
    assert!(
        !String::from_utf8_lossy(&serde_json::to_vec(&first).unwrap())
            .contains("qualification answer")
    );

    let replay = invoke();
    assert!(replay.status.success(), "{:?}", replay.stderr);
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["disposition"], "qualified_completion");
    assert_eq!(replay["replayed"], true);

    let catalogue = Command::new(executable)
        .arg("--describe-providers")
        .arg(&config)
        .output()
        .unwrap();
    assert!(catalogue.status.success());
    let catalogue: serde_json::Value = serde_json::from_slice(&catalogue.stdout).unwrap();
    let qualification = &catalogue["providers"][0]["qualification"];
    assert_eq!(qualification["disposition"], "qualified_completion");
    assert_eq!(qualification["completion"], true);
    assert_eq!(qualification["tool_continuation"], "not_exercised");
    assert_eq!(qualification["replayed"], false);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_retains_content_free_http_diagnostic_without_narrowing_unknown_outcome() {
    let root = std::env::temp_dir().join(format!(
        "daimon-model-qualification-diagnostic-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        sent.send(()).unwrap();
        let body = br#"{"error":"schema feature unsupported","secret":"must not escape"}"#;
        write!(
            stream,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });

    let config = root.join("model.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&json!({
            "principal": "01010101010101010101010101010101",
            "aegis_socket": root.join("aegis.sock"),
            "aegis_expected_epoch": 0,
            "aegis_grant_now": 1,
            "aegis_grant_expires_at": 1000,
            "chronos_socket": root.join("chronos.sock"),
            "daimon_socket": root.join("model.sock"),
            "store_directory": root.join("store"),
            "provider": {
                "provider_id": "02020202020202020202020202020202",
                "harness_profile_id": "03030303030303030303030303030303",
                "model": "diagnostic-local-model",
                "address": address.to_string(),
                "host_header": address.to_string(),
                "path": "/v1/chat/completions",
                "structured_output": true,
                "structured_tools": false,
                "sampling_temperature_milli": 0,
                "connect_timeout_ms": 1000,
                "io_timeout_ms": 1000,
                "max_request_bytes": 65536,
                "max_response_bytes": 65536
            },
            "task_bindings": [{
                "external_task_key": "04040404040404040404040404040404",
                "chronos_task_id": "qualification-diagnostic-task"
            }],
            "context": [{
                "reference": "05050505050505050505050505050505",
                "kind": "chronos_work",
                "text": "bounded work"
            }],
            "messages": [{"role": "system", "content": "answer carefully"}],
            "io_timeout_ms": 1000,
            "max_executions": 8,
            "max_requests_per_connection": 4
        }))
        .unwrap(),
    )
    .unwrap();

    let executable = env!("CARGO_BIN_EXE_daimon-local-model");
    let catalogue = Command::new(executable)
        .arg("--describe-providers")
        .arg(&config)
        .output()
        .unwrap();
    assert!(catalogue.status.success());
    let catalogue: serde_json::Value = serde_json::from_slice(&catalogue.stdout).unwrap();
    let request = serde_json::to_vec(&json!({
        "version": 1,
        "operation_id": "07070707070707070707070707070707",
        "expected_document_digest": catalogue["document_digest"]
    }))
    .unwrap();
    let invoke = || {
        let mut child = Command::new(executable)
            .arg("--qualify-provider")
            .arg(&config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&request).unwrap();
        child.wait_with_output().unwrap()
    };

    let first = invoke();
    assert!(first.status.success(), "{:?}", first.stderr);
    received.recv().unwrap();
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["disposition"], "outcome_unknown");
    assert_eq!(first["completion"], false);
    assert_eq!(first["diagnostic_kind"], "http_status:400");
    assert!(
        first["diagnostic_response_digest"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:"))
    );
    let projection = String::from_utf8(serde_json::to_vec(&first).unwrap()).unwrap();
    assert!(!projection.contains("schema feature unsupported"));
    assert!(!projection.contains("must not escape"));

    let replay = invoke();
    assert!(replay.status.success(), "{:?}", replay.stderr);
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["disposition"], "outcome_unknown");
    assert_eq!(replay["diagnostic_kind"], "http_status:400");
    assert_eq!(replay["replayed"], true);

    fs::remove_dir_all(root).unwrap();
}
