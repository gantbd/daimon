#![cfg(unix)]

use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn executable_projects_validated_local_model_without_endpoint_secrets() {
    let root = std::env::temp_dir().join(format!(
        "daimon-model-catalog-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let config = root.join("model.json");
    let value = serde_json::json!({
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
            "model": "qwen/qwen3-coder-next",
            "address": "127.0.0.1:1234",
            "host_header": "localhost:1234",
            "path": "/v1/chat/completions",
            "structured_output": false,
            "structured_tools": true,
            "sampling_temperature_milli": 0,
            "connect_timeout_ms": 100,
            "io_timeout_ms": 1000,
            "max_request_bytes": 65536,
            "max_response_bytes": 65536
        },
        "task_bindings": [{
            "external_task_key": "04040404040404040404040404040404",
            "chronos_task_id": "catalog-task"
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
    fs::write(&config, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_daimon-local-model"))
        .arg("--describe-providers")
        .arg(&config)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let catalog: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(catalog["version"], 1);
    assert_eq!(catalog["owner"], "daimon-local-model");
    assert_eq!(catalog["providers"][0]["model"], "qwen/qwen3-coder-next");
    assert_eq!(catalog["providers"][0]["endpoint_scope"], "loopback");
    assert_eq!(catalog["providers"][0]["endpoint_port"], 1234);
    assert_eq!(catalog["providers"][0]["structured_tools"], true);
    let projection = String::from_utf8(output.stdout).unwrap();
    assert!(!projection.contains("host_header"));
    assert!(!projection.contains("/v1/chat/completions"));
    assert!(!projection.contains("bearer_token_env"));
    fs::remove_dir_all(root).unwrap();
}
