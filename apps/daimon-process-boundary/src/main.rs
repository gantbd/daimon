//! Sole-owner process-group sidecar for governed Daimon terminal callbacks.
//!
//! The parent owns this process through framed stdin. EOF is owner loss: the
//! whole process group is killed and the direct child is reaped before exit.

#![forbid(unsafe_code)]

use base64::Engine as _;
use processkit::{Command, OutputBufferPolicy, ProcessGroup, StdioMode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_STREAM_CHUNK_BYTES: usize = 65_536;
const OUTPUT_QUEUE_DEPTH: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Start {
        argv: Vec<String>,
        cwd: String,
        #[serde(default)]
        env: Vec<[String; 2]>,
        env_clear: bool,
    },
    OutputAck,
    Cancel,
}

#[derive(Debug)]
enum OutputEvent {
    Bytes(&'static str, Vec<u8>),
    Closed,
}

struct ChannelWriter {
    sender: PollSender<OutputEvent>,
    stream: &'static str,
    closed: bool,
}

impl ChannelWriter {
    fn new(sender: mpsc::Sender<OutputEvent>, stream: &'static str) -> Self {
        Self {
            sender: PollSender::new(sender),
            stream,
            closed: false,
        }
    }
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after stream close",
            )));
        }
        ready!(self.sender.poll_reserve(cx)).map_err(io::Error::other)?;
        let length = bytes.len();
        let stream = self.stream;
        self.sender
            .send_item(OutputEvent::Bytes(stream, bytes.to_vec()))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        ready!(self.sender.poll_reserve(cx)).map_err(io::Error::other)?;
        self.sender
            .send_item(OutputEvent::Closed)
            .map_err(io::Error::other)?;
        self.closed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[derive(Clone, Copy)]
enum StopCause {
    Natural,
    Cancelled,
    OwnerLost,
}

#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("--probe") {
        println!("daimon-process-boundary/0.1");
        return;
    }
    if let Err(error) = serve().await {
        let _ =
            write_frame(&json!({"event": "error", "reason": bounded(&error.to_string())})).await;
        std::process::exit(1);
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut protocol_output = tokio::io::stdout();
    let first = read_frame(&mut std::io::stdin().lock())?;
    let Request::Start {
        argv,
        cwd,
        env,
        env_clear,
    } = serde_json::from_slice(&first)?
    else {
        return Err("first frame must be start".into());
    };
    validate_start(&argv, &cwd, &env, env_clear)?;

    let group = ProcessGroup::new()?;
    let mechanism = group.mechanism().name();
    let (output_tx, mut output_rx) = mpsc::channel(OUTPUT_QUEUE_DEPTH);
    let mut command = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(&cwd)
        .stdout(StdioMode::Piped)
        .stderr(StdioMode::Piped)
        .output_buffer(OutputBufferPolicy::bounded(64).with_max_bytes(MAX_STREAM_CHUNK_BYTES))
        .stdout_raw_tee(ChannelWriter::new(output_tx.clone(), "stdout"))
        .stderr_raw_tee(ChannelWriter::new(output_tx.clone(), "stderr"));
    if env_clear {
        command = command.env_clear();
    }
    command = command.envs(env.iter().map(|pair| (&pair[0], &pair[1])));
    drop(output_tx);

    let run = group.start(&command).await?;
    drop(command);
    let pid = run.pid().ok_or("process started without pid")?;
    let mut finish = tokio::spawn(async move { run.finish().await });
    write_frame_to(
        &mut protocol_output,
        &json!({"event": "started", "pid": pid, "mechanism": mechanism}),
    )
    .await?;

    let (control_tx, mut control_rx) = mpsc::channel(16);
    std::thread::Builder::new()
        .name("daimon-process-boundary-control".to_owned())
        .spawn(move || {
            let input = std::io::stdin();
            let mut input = input.lock();
            loop {
                match read_frame(&mut input) {
                    Ok(frame) => {
                        let request = serde_json::from_slice::<Request>(&frame)
                            .map_err(|error| error.to_string());
                        if control_tx.blocking_send(request).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(error) => {
                        let _ = control_tx.blocking_send(Err(error.to_string()));
                        break;
                    }
                }
            }
        })?;

    let mut closed_streams = 0_usize;
    let mut output_credit = true;
    let (cause, mut finished) = loop {
        tokio::select! {
            result = &mut finish => {
                let result = result.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
                break (StopCause::Natural, Some(result));
            }
            control = control_rx.recv() => match control {
                Some(Ok(Request::OutputAck)) => output_credit = true,
                Some(Ok(Request::Cancel)) => break (StopCause::Cancelled, None),
                Some(Ok(Request::Start { .. })) => {
                    write_frame_to(&mut protocol_output, &json!({"event": "control_error", "reason": "already_started"})).await?;
                }
                Some(Err(reason)) => {
                    write_frame_to(&mut protocol_output, &json!({"event": "control_error", "reason": bounded(&reason)})).await?;
                }
                None => break (StopCause::OwnerLost, None),
            },
            output = output_rx.recv(), if output_credit => match output {
                Some(OutputEvent::Bytes(stream, bytes)) => {
                    write_frame_to(&mut protocol_output, &json!({
                        "event": "output",
                        "stream": stream,
                        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                    })).await?;
                    output_credit = false;
                }
                Some(OutputEvent::Closed) => closed_streams += 1,
                None => closed_streams = 2,
            },
        }
    };

    if !matches!(cause, StopCause::Natural) {
        let _ = group.kill_all();
    }
    if finished.is_none() {
        finished = Some(
            finish
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?,
        );
    }
    let mut owner_lost = matches!(cause, StopCause::OwnerLost);
    while closed_streams < 2 {
        tokio::select! {
            control = control_rx.recv(), if !owner_lost => match control {
                Some(Ok(Request::OutputAck)) => output_credit = true,
                None => owner_lost = true,
                _ => {}
            },
            output = output_rx.recv(), if closed_streams < 2 && (owner_lost || output_credit) => match output {
                Some(OutputEvent::Bytes(stream, bytes)) if !owner_lost => {
                    write_frame_to(&mut protocol_output, &json!({
                        "event": "output",
                        "stream": stream,
                        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                    })).await?;
                    output_credit = false;
                }
                Some(OutputEvent::Bytes(_, _)) => {}
                Some(OutputEvent::Closed) => closed_streams += 1,
                None => closed_streams = 2,
            }
        }
    }
    if !owner_lost {
        let outcome = finished.expect("finish completed").outcome;
        let (kind, code, signal) = match cause {
            StopCause::Natural => (outcome.name(), outcome.code(), outcome.signal()),
            StopCause::Cancelled => ("cancelled", None, None),
            StopCause::OwnerLost => unreachable!(),
        };
        write_frame_to(
            &mut protocol_output,
            &json!({"event": "exited", "kind": kind, "code": code, "signal": signal}),
        )
        .await?;
    }
    Ok(())
}

fn validate_start(
    argv: &[String],
    cwd: &str,
    env: &[[String; 2]],
    env_clear: bool,
) -> Result<(), &'static str> {
    if argv.is_empty()
        || argv.len() > 256
        || !std::path::Path::new(&argv[0]).is_absolute()
        || argv
            .iter()
            .any(|value| value.is_empty() || value.len() > 4096 || value.contains('\0'))
    {
        return Err("invalid_argv");
    }
    if cwd.is_empty() || cwd.len() > 16_384 || cwd.contains('\0') {
        return Err("invalid_cwd");
    }
    if !env_clear
        || env.len() > 64
        || env
            .iter()
            .map(|pair| &pair[0])
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != env.len()
        || env
            .iter()
            .map(|pair| pair[0].len().saturating_add(pair[1].len()))
            .sum::<usize>()
            > MAX_FRAME_BYTES
        || env.iter().any(|pair| {
            pair[0].is_empty()
                || pair[0].len() > 256
                || pair[1].len() > 65_536
                || pair[0].contains('\0')
                || pair[1].contains('\0')
                || !valid_environment_name(&pair[0])
        })
    {
        return Err("invalid_env");
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

fn read_frame(reader: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

async fn write_frame(value: &Value) -> io::Result<()> {
    write_frame_to(&mut tokio::io::stdout(), value).await
}

async fn write_frame_to(output: &mut (impl AsyncWrite + Unpin), value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    output.write_u32(length).await?;
    output.write_all(&bytes).await?;
    output.flush().await
}

fn bounded(value: &str) -> &str {
    let mut end = value.len().min(1024);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_requires_absolute_argv_and_an_explicit_clean_unique_environment() {
        let argv = vec!["/bin/echo".to_owned()];
        assert_eq!(validate_start(&argv, "/tmp", &[], true), Ok(()));
        assert_eq!(
            validate_start(&["echo".to_owned()], "/tmp", &[], true),
            Err("invalid_argv")
        );
        assert_eq!(
            validate_start(&argv, "/tmp", &[], false),
            Err("invalid_env")
        );
        assert_eq!(
            validate_start(
                &argv,
                "/tmp",
                &[
                    ["MODE".to_owned(), "one".to_owned()],
                    ["MODE".to_owned(), "two".to_owned()]
                ],
                true
            ),
            Err("invalid_env")
        );
        assert_eq!(
            validate_start(
                &argv,
                "/tmp",
                &[["BAD=NAME".to_owned(), "value".to_owned()]],
                true
            ),
            Err("invalid_env")
        );
    }
}
