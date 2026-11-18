#![cfg(unix)]

use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Output, Stdio},
};

fn run(executable: &str, command: &str, config: &Path, request: &Value) -> Output {
    let mut child = Command::new(executable)
        .arg(command)
        .arg(config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(request).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn provider(model: &str) -> Value {
    json!({
        "provider_id": "02020202020202020202020202020202",
        "harness_profile_id": "03030303030303030303030303030303",
        "model": model,
        "address": "127.0.0.1:1234",
        "host_header": "private-host-header",
        "path": "/private/chat/completions",
        "bearer_token_env": "PRIVATE_TOKEN_NAME",
        "structured_output": false,
        "structured_tools": true,
        "sampling_temperature_milli": 0,
        "connect_timeout_ms": 1000,
        "io_timeout_ms": 1000,
        "max_request_bytes": 65536,
        "max_response_bytes": 65536
    })
}

#[test]
fn executable_plans_applies_and_replays_redacted_model_provider_edit() {
    let root =
        std::env::temp_dir().join(format!("daimon-model-provider-edit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let config = root.join("model.json");
    let document = json!({
        "principal": "01010101010101010101010101010101",
        "aegis_socket": root.join("aegis.sock"),
        "aegis_expected_epoch": 0,
        "aegis_grant_now": 1,
        "aegis_grant_expires_at": 1000,
        "chronos_socket": root.join("chronos.sock"),
        "daimon_socket": root.join("model.sock"),
        "store_directory": root.join("store"),
        "provider": provider("old-model"),
        "task_bindings": [{
            "external_task_key": "04040404040404040404040404040404",
            "chronos_task_id": "provider-edit-task"
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
    });
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o640)
        .open(&config)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(&document).unwrap())
        .unwrap();
    drop(file);

    let executable = env!("CARGO_BIN_EXE_daimon-local-model");
    let form = Command::new(executable)
        .arg("--describe-provider-edit")
        .arg(&config)
        .output()
        .unwrap();
    assert!(form.status.success());
    let form_text = String::from_utf8(form.stdout).unwrap();
    assert!(form_text.contains("PRIVATE_TOKEN_NAME"));
    assert!(!form_text.contains("never-project-this-secret"));
    assert!(form_text.contains("\"secret_values_projected\":false"));
    let catalogue = Command::new(executable)
        .arg("--describe-providers")
        .arg(&config)
        .env("PRIVATE_TOKEN_NAME", "never-project-this-secret")
        .output()
        .unwrap();
    assert!(catalogue.status.success());
    let catalogue: Value = serde_json::from_slice(&catalogue.stdout).unwrap();
    let operation_id = "06060606060606060606060606060606";
    let candidate = provider("new-model");
    let plan_request = json!({
        "version": 1,
        "operation_id": operation_id,
        "expected_document_digest": catalogue["document_digest"],
        "provider": candidate
    });
    let planned = run(executable, "--plan-provider-edit", &config, &plan_request);
    assert!(planned.status.success(), "{:?}", planned.stderr);
    let plan: Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(plan["owner"], "daimon-local-model");
    assert_eq!(plan["action"], "replace");
    assert_eq!(plan["changed_fields"], json!(["model"]));
    assert_eq!(plan["restart_required"], true);
    assert_eq!(plan["qualification_required"], true);
    assert_eq!(plan["provider"]["model"], "new-model");
    let projection = String::from_utf8(planned.stdout).unwrap();
    assert!(!projection.contains("private-host-header"));
    assert!(!projection.contains("/private/chat/completions"));
    assert!(!projection.contains("PRIVATE_TOKEN_NAME"));

    let apply_request = json!({
        "version": 1,
        "operation_id": operation_id,
        "expected_document_digest": plan["expected_document_digest"],
        "expected_plan_digest": plan["plan_digest"],
        "expected_candidate_document_digest": plan["candidate_document_digest"],
        "provider": candidate
    });
    let applied = run(executable, "--apply-provider-edit", &config, &apply_request);
    assert!(applied.status.success(), "{:?}", applied.stderr);
    let receipt: Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(receipt["disposition"], "applied");
    assert_eq!(receipt["qualification_required"], true);
    assert_eq!(
        receipt["document_digest"],
        plan["candidate_document_digest"]
    );
    let persisted: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    assert_eq!(persisted["provider"]["model"], "new-model");
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o640
    );

    let replay = run(executable, "--apply-provider-edit", &config, &apply_request);
    assert!(replay.status.success(), "{:?}", replay.stderr);
    let replay: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["disposition"], "already_applied");
    assert_eq!(replay["replayed"], true);

    let stale = run(executable, "--plan-provider-edit", &config, &plan_request);
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("owner document changed"));

    fs::remove_dir_all(root).unwrap();
}
