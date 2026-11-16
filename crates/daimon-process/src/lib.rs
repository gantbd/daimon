//! Digest-bound provider process launch isolation.

#![forbid(unsafe_code)]

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread;
use std::time::Duration;

pub const MAX_SEATBELT_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_TERMINAL_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_BOUNDARY_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationErrorV1 {
    InvalidPolicy,
    DigestMismatch,
    UnsupportedPlatform,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProcessBoundaryLaunchV1 {
    pub boundary_program: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub environment: Vec<(String, String)>,
    pub output_byte_limit: usize,
    pub startup_timeout: Duration,
    pub cancellation_timeout: Duration,
}

impl std::fmt::Debug for ProcessBoundaryLaunchV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessBoundaryLaunchV1")
            .field("boundary_program", &self.boundary_program)
            .field("argv", &format_args!("<{} redacted>", self.argv.len()))
            .field("cwd", &"<redacted>")
            .field(
                "environment",
                &format_args!("<{} redacted>", self.environment.len()),
            )
            .field("output_byte_limit", &self.output_byte_limit)
            .field("startup_timeout", &self.startup_timeout)
            .field("cancellation_timeout", &self.cancellation_timeout)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessBoundaryErrorV1 {
    Invalid,
    Spawn,
    Protocol,
    Timeout,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessBoundaryExitV1 {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessBoundaryOutputV1 {
    pub output: Vec<u8>,
    pub truncated: bool,
    pub exit: Option<ProcessBoundaryExitV1>,
}

enum BoundaryFrameV1 {
    Message(Value),
    Invalid,
    Eof,
}

/// Synchronous owner for one process-boundary sidecar. The background thread
/// owns only framed stdout; this value is the sole control writer and child
/// owner. Dropping it closes control input before waiting for group cleanup.
pub struct ProcessBoundaryV1 {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    frames: Receiver<BoundaryFrameV1>,
    output: Vec<u8>,
    output_limit: usize,
    truncated: bool,
    exit: Option<ProcessBoundaryExitV1>,
    mechanism: String,
    cancellation_timeout: Duration,
}

impl std::fmt::Debug for ProcessBoundaryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessBoundaryV1")
            .field("child", &self.child.as_ref().map(Child::id))
            .field(
                "output",
                &format_args!("<{} bytes redacted>", self.output.len()),
            )
            .field("output_limit", &self.output_limit)
            .field("truncated", &self.truncated)
            .field("exit", &self.exit)
            .field("mechanism", &self.mechanism)
            .finish()
    }
}

impl ProcessBoundaryV1 {
    pub fn start(launch: &ProcessBoundaryLaunchV1) -> Result<Self, ProcessBoundaryErrorV1> {
        validate_boundary_launch(launch)?;
        let mut command = Command::new(&launch.boundary_program);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| ProcessBoundaryErrorV1::Spawn)?;
        let mut stdin = child.stdin.take().ok_or(ProcessBoundaryErrorV1::Spawn)?;
        let stdout = child.stdout.take().ok_or(ProcessBoundaryErrorV1::Spawn)?;
        let (sender, frames) = mpsc::sync_channel(64);
        thread::Builder::new()
            .name("daimon-process-boundary-reader".to_owned())
            .spawn(move || read_boundary_frames(stdout, sender))
            .map_err(|_| ProcessBoundaryErrorV1::Spawn)?;
        let env = launch
            .environment
            .iter()
            .map(|(name, value)| [name, value])
            .collect::<Vec<_>>();
        if write_boundary_frame(
            &mut stdin,
            &json!({
                "op": "start",
                "argv": launch.argv,
                "cwd": launch.cwd.to_str().expect("validated UTF-8 cwd"),
                "env": env,
                "env_clear": true
            }),
        )
        .is_err()
        {
            drop(stdin);
            let _ = child.wait();
            return Err(ProcessBoundaryErrorV1::Protocol);
        }
        let started = match frames.recv_timeout(launch.startup_timeout) {
            Ok(BoundaryFrameV1::Message(value)) => value,
            Err(RecvTimeoutError::Timeout) => {
                drop(stdin);
                let _ = child.wait();
                return Err(ProcessBoundaryErrorV1::Timeout);
            }
            _ => {
                drop(stdin);
                let _ = child.wait();
                return Err(ProcessBoundaryErrorV1::Protocol);
            }
        };
        let mechanism = started
            .get("mechanism")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .map(str::to_owned);
        if started.get("event").and_then(Value::as_str) != Some("started")
            || started.get("pid").and_then(Value::as_u64).is_none()
            || mechanism.is_none()
        {
            drop(stdin);
            let _ = child.wait();
            return Err(ProcessBoundaryErrorV1::Protocol);
        }
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            frames,
            output: Vec::new(),
            output_limit: launch.output_byte_limit,
            truncated: false,
            exit: None,
            mechanism: mechanism.expect("validated mechanism"),
            cancellation_timeout: launch.cancellation_timeout,
        })
    }

    pub fn mechanism(&self) -> &str {
        &self.mechanism
    }

    pub fn output(&mut self) -> Result<ProcessBoundaryOutputV1, ProcessBoundaryErrorV1> {
        self.drain_available()?;
        Ok(self.output_snapshot())
    }

    pub fn poll_exit(&mut self) -> Result<Option<ProcessBoundaryExitV1>, ProcessBoundaryErrorV1> {
        self.drain_available()?;
        Ok(self.exit)
    }

    pub fn cancel(&mut self) -> Result<ProcessBoundaryExitV1, ProcessBoundaryErrorV1> {
        if let Some(exit) = self.exit {
            return Ok(exit);
        }
        let stdin = self.stdin.as_mut().ok_or(ProcessBoundaryErrorV1::Closed)?;
        write_boundary_frame(stdin, &json!({"op": "cancel"}))?;
        let deadline = std::time::Instant::now()
            .checked_add(self.cancellation_timeout)
            .ok_or(ProcessBoundaryErrorV1::Timeout)?;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match self.frames.recv_timeout(remaining) {
                Ok(frame) => self.accept_frame(frame)?,
                Err(RecvTimeoutError::Timeout) => return Err(ProcessBoundaryErrorV1::Timeout),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(ProcessBoundaryErrorV1::Protocol);
                }
            }
            if let Some(exit) = self.exit {
                return Ok(exit);
            }
        }
    }

    fn drain_available(&mut self) -> Result<(), ProcessBoundaryErrorV1> {
        loop {
            match self.frames.try_recv() {
                Ok(frame) => self.accept_frame(frame)?,
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) if self.exit.is_some() => return Ok(()),
                Err(TryRecvError::Disconnected) => return Err(ProcessBoundaryErrorV1::Protocol),
            }
        }
    }

    fn accept_frame(&mut self, frame: BoundaryFrameV1) -> Result<(), ProcessBoundaryErrorV1> {
        let value = match frame {
            BoundaryFrameV1::Message(value) => value,
            BoundaryFrameV1::Eof if self.exit.is_some() => return Ok(()),
            BoundaryFrameV1::Invalid | BoundaryFrameV1::Eof => {
                return Err(ProcessBoundaryErrorV1::Protocol);
            }
        };
        match value.get("event").and_then(Value::as_str) {
            Some("output") => {
                let encoded = value
                    .get("data")
                    .and_then(Value::as_str)
                    .ok_or(ProcessBoundaryErrorV1::Protocol)?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| ProcessBoundaryErrorV1::Protocol)?;
                if bytes.len() > 65_536 {
                    return Err(ProcessBoundaryErrorV1::Protocol);
                }
                self.append_output(&bytes);
                let stdin = self.stdin.as_mut().ok_or(ProcessBoundaryErrorV1::Closed)?;
                write_boundary_frame(stdin, &json!({"op": "output_ack"}))
            }
            Some("exited") => {
                let kind = value
                    .get("kind")
                    .and_then(Value::as_str)
                    .ok_or(ProcessBoundaryErrorV1::Protocol)?;
                let exit_code = optional_i32(value.get("code"))?;
                let signal = optional_i32(value.get("signal"))?;
                let cancelled = kind == "cancelled";
                if !cancelled && kind != "exited" && kind != "signalled" {
                    return Err(ProcessBoundaryErrorV1::Protocol);
                }
                self.exit = Some(ProcessBoundaryExitV1 {
                    exit_code,
                    signal,
                    cancelled,
                });
                self.settle_sidecar()?;
                Ok(())
            }
            _ => Err(ProcessBoundaryErrorV1::Protocol),
        }
    }

    fn append_output(&mut self, bytes: &[u8]) {
        let reserve = self.output_limit.saturating_add(4);
        self.output.extend_from_slice(bytes);
        if self.output.len() > reserve {
            let drop_count = self.output.len() - reserve;
            self.output.drain(..drop_count);
            self.truncated = true;
        }
    }

    fn output_snapshot(&self) -> ProcessBoundaryOutputV1 {
        let normalized = String::from_utf8_lossy(&self.output);
        let bytes = normalized.as_bytes();
        let output = utf8_suffix(bytes, self.output_limit).to_vec();
        ProcessBoundaryOutputV1 {
            truncated: self.truncated || output.len() < bytes.len(),
            output,
            exit: self.exit,
        }
    }

    fn settle_sidecar(&mut self) -> Result<(), ProcessBoundaryErrorV1> {
        self.stdin.take();
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        child.wait().map_err(|_| ProcessBoundaryErrorV1::Protocol)?;
        Ok(())
    }
}

impl Drop for ProcessBoundaryV1 {
    fn drop(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

fn validate_boundary_launch(
    launch: &ProcessBoundaryLaunchV1,
) -> Result<(), ProcessBoundaryErrorV1> {
    if !launch.boundary_program.is_absolute()
        || !launch.boundary_program.is_file()
        || launch.argv.is_empty()
        || launch.argv.len() > 256
        || !Path::new(&launch.argv[0]).is_absolute()
        || launch
            .argv
            .iter()
            .any(|value| value.is_empty() || value.len() > 4096 || value.contains('\0'))
        || !launch.cwd.is_absolute()
        || !launch.cwd.is_dir()
        || launch.cwd.to_str().is_none()
        || launch.environment.len() > 64
        || launch
            .environment
            .iter()
            .map(|(name, _)| name)
            .collect::<BTreeSet<_>>()
            .len()
            != launch.environment.len()
        || launch
            .environment
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .sum::<usize>()
            > MAX_BOUNDARY_FRAME_BYTES
        || launch.environment.iter().any(|(name, value)| {
            name.is_empty()
                || name.len() > 256
                || value.len() > 65_536
                || name.contains('\0')
                || value.contains('\0')
                || !valid_environment_name(name)
        })
        || launch.output_byte_limit > MAX_TERMINAL_OUTPUT_BYTES
        || launch.startup_timeout.is_zero()
        || launch.cancellation_timeout.is_zero()
    {
        return Err(ProcessBoundaryErrorV1::Invalid);
    }
    Ok(())
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn read_boundary_frames(mut stdout: impl Read, sender: mpsc::SyncSender<BoundaryFrameV1>) {
    loop {
        let mut header = [0_u8; 4];
        match stdout.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                let _ = sender.send(BoundaryFrameV1::Eof);
                return;
            }
            Err(_) => {
                let _ = sender.send(BoundaryFrameV1::Invalid);
                return;
            }
        }
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > MAX_BOUNDARY_FRAME_BYTES {
            let _ = sender.send(BoundaryFrameV1::Invalid);
            return;
        }
        let mut bytes = vec![0_u8; length];
        if stdout.read_exact(&mut bytes).is_err() {
            let _ = sender.send(BoundaryFrameV1::Invalid);
            return;
        }
        let frame = serde_json::from_slice(&bytes)
            .ok()
            .filter(Value::is_object)
            .map_or(BoundaryFrameV1::Invalid, BoundaryFrameV1::Message);
        if sender.send(frame).is_err() {
            return;
        }
    }
}

fn write_boundary_frame(
    output: &mut impl Write,
    value: &Value,
) -> Result<(), ProcessBoundaryErrorV1> {
    let bytes = serde_json::to_vec(value).map_err(|_| ProcessBoundaryErrorV1::Protocol)?;
    if bytes.is_empty() || bytes.len() > MAX_BOUNDARY_FRAME_BYTES {
        return Err(ProcessBoundaryErrorV1::Protocol);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ProcessBoundaryErrorV1::Protocol)?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|()| output.write_all(&bytes))
        .and_then(|()| output.flush())
        .map_err(|_| ProcessBoundaryErrorV1::Protocol)
}

fn optional_i32(value: Option<&Value>) -> Result<Option<i32>, ProcessBoundaryErrorV1> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .map(Some)
            .ok_or(ProcessBoundaryErrorV1::Protocol),
    }
}

fn utf8_suffix(bytes: &[u8], maximum: usize) -> &[u8] {
    if bytes.len() <= maximum {
        return bytes;
    }
    if maximum == 0 {
        return &[];
    }
    let mut start = bytes.len() - maximum;
    while start < bytes.len() && std::str::from_utf8(&bytes[start..]).is_err() {
        start += 1;
    }
    &bytes[start..]
}

#[derive(Clone, Default, Eq, PartialEq)]
pub enum ProcessIsolationV1 {
    #[default]
    Direct,
    MacosSeatbelt(MacosSeatbeltV1),
}

#[derive(Clone, Eq, PartialEq)]
pub struct MacosSeatbeltV1 {
    policy: String,
    policy_digest: [u8; 32],
}

impl std::fmt::Debug for ProcessIsolationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => formatter.write_str("Direct"),
            Self::MacosSeatbelt(value) => formatter
                .debug_struct("MacosSeatbelt")
                .field("policy", &"<redacted>")
                .field("policy_digest", &value.policy_digest)
                .finish(),
        }
    }
}

impl ProcessIsolationV1 {
    pub fn macos_seatbelt(
        policy: Vec<u8>,
        expected_digest: [u8; 32],
    ) -> Result<Self, IsolationErrorV1> {
        if !cfg!(target_os = "macos") {
            return Err(IsolationErrorV1::UnsupportedPlatform);
        }
        if policy.is_empty() || policy.len() > MAX_SEATBELT_POLICY_BYTES || policy.contains(&0) {
            return Err(IsolationErrorV1::InvalidPolicy);
        }
        let actual: [u8; 32] = Sha256::digest(&policy).into();
        if actual != expected_digest {
            return Err(IsolationErrorV1::DigestMismatch);
        }
        let policy = String::from_utf8(policy).map_err(|_| IsolationErrorV1::InvalidPolicy)?;
        Ok(Self::MacosSeatbelt(MacosSeatbeltV1 {
            policy,
            policy_digest: expected_digest,
        }))
    }

    pub const fn identity(&self) -> (u8, Option<[u8; 32]>) {
        match self {
            Self::Direct => (0, None),
            Self::MacosSeatbelt(value) => (1, Some(value.policy_digest)),
        }
    }

    pub fn command(&self, program: &Path) -> Result<Command, IsolationErrorV1> {
        match self {
            Self::Direct => Ok(Command::new(program)),
            Self::MacosSeatbelt(value) => {
                if !cfg!(target_os = "macos") {
                    return Err(IsolationErrorV1::UnsupportedPlatform);
                }
                let mut command = Command::new("/usr/bin/sandbox-exec");
                command.arg("-p").arg(&value.policy).arg(program);
                Ok(command)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_bytes_and_identity_are_digest_bound_and_debug_redacted() {
        if !cfg!(target_os = "macos") {
            return;
        }
        let policy = b"(version 1) (deny default)".to_vec();
        let digest: [u8; 32] = Sha256::digest(&policy).into();
        let isolation = ProcessIsolationV1::macos_seatbelt(policy.clone(), digest).unwrap();
        assert_eq!(isolation.identity(), (1, Some(digest)));
        assert!(!format!("{isolation:?}").contains("deny default"));
        let mut changed = digest;
        changed[0] ^= 1;
        assert_eq!(
            ProcessIsolationV1::macos_seatbelt(policy, changed),
            Err(IsolationErrorV1::DigestMismatch)
        );
    }
}
