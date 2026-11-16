#![cfg(target_os = "macos")]

use daimon_process::ProcessIsolationV1;
use sha2::{Digest, Sha256};
use std::path::Path;

const POLICY: &str =
    "(version 1) (deny default) (allow process-exec) (allow file-read*) (allow sysctl-read)";

#[test]
fn deny_default_policy_allows_stdio_but_denies_file_mutation() {
    let digest: [u8; 32] = Sha256::digest(POLICY.as_bytes()).into();
    let isolation = ProcessIsolationV1::macos_seatbelt(POLICY.as_bytes().to_vec(), digest).unwrap();
    let output = isolation
        .command(Path::new("/bin/sh"))
        .unwrap()
        .args(["-c", "printf sandbox-ok"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"sandbox-ok");

    let target =
        std::env::temp_dir().join(format!("daimon-seatbelt-denied-{}", std::process::id()));
    let script = format!("printf forbidden > {}", target.display());
    let denied = isolation
        .command(Path::new("/bin/sh"))
        .unwrap()
        .args(["-c", &script])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(!target.exists());
}
