# Daimon local agent

`daimon-local-agent` is the production composition root for Daimon's durable
interactive-agent service. It connects only through Aegis and Chronos public
clients, owns one exclusive checkpoint directory and authenticated private
agent socket, and routes frozen profiles to ACP or Claude stream-JSON adapters.

Validate complete configuration without connecting to a peer, opening storage,
binding a socket, or starting a provider:

```text
cargo run -p daimon-local-agent --locked --offline -- \
  --check config/local-agent.example.json
```

Deployment supervisors may select `--supervised CONFIG.json`. The process then
accepts one exact `x` byte on standard input as a drain request, finishes the
current bounded connection, drops the daemon so its owned socket is removed,
and exits successfully. EOF and other bytes are not shutdown authority. This
control channel carries no Daimon command, provider input, credential, or
checkpoint content.

Provider programs, arguments, inherited environment names, and workspace paths
are deployment-owned. Public protocol and checkpoint state retain only opaque
identities and credential-free digests. A profile document digest is derived by
the application from its exact provider, harness, wire, command, and policy
fields; operators cannot supply a contradictory document digest.

Each provider may additionally select a digest-bound macOS Seatbelt policy:

```json
"isolation": {
  "kind": "macos_seatbelt",
  "policy_path": "/absolute/deployment/provider.sb",
  "policy_digest": "sha256:..."
}
```

`--check` reads the bounded policy and verifies its digest without launching a
process. Runtime passes those retained exact bytes to `sandbox-exec -p`; policy
path drift cannot change confinement silently, and the isolation kind/digest is
part of the frozen command identity. Omitted isolation is explicit direct mode
and is not a production sandbox claim. Policy adequacy remains deployment-owned;
the supplied qualification proves deny-default enforcement and adapter
negotiation, while a non-macOS backend remains open.

Aegis grants are session-bound and therefore are never accepted from config.
The application issues its exact profile/tool grant on the same authenticated
Aegis connection it later uses for authorization, under configured epoch and
logical-time bounds.

ACP client filesystem reads are disabled unless a workspace declares an exact
governed scope:

```json
"acp_file_read": {
  "capability": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
  "paths": ["Cargo.toml", "src"],
  "max_bytes": 1048576
}
```

The capability must also appear in `tool_capabilities` and in both the agent
open and prompt execution requests. Paths are workspace-relative deployment
configuration. `--check` canonicalizes them, rejects missing paths, aliases and
symlink escapes, and caps reads at the ACP event bound. Each callback receives
the exact canonical session, turn, workspace, execution/attempt and current
continuation logical time. The production governor reauthorizes that execution
through the same live session-bound Aegis client, revalidates the exact running
Chronos attempt, resolves the requested absolute path through the canonical
scope, reads bounded UTF-8, and retains only a safe relative path, digest and
byte count as provider evidence. Filesystem writes and terminals remain
unadvertised unless separately configured. Provider-native filesystem tools do
not cross this callback and still require process isolation as a separate
control.

ACP client terminals are likewise disabled unless the workspace declares a
governed scope:

```json
"acp_terminal": {
  "capability": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
  "boundary_program": "/absolute/path/to/daimon-process-boundary",
  "commands": [{
    "command": "cargo",
    "program": "/absolute/path/to/cargo",
    "argument_prefix": ["test"]
  }],
  "environment_names": ["RUST_BACKTRACE"],
  "max_handles": 2,
  "max_output_bytes": 1048576
}
```

The capability must be part of the application-issued grant. `--check`
canonicalizes the workspace, boundary, and target executables and rejects
aliases, duplicate command/environment names, invalid limits, and relative or
missing programs. At create time the governor rechecks current Aegis authority
and the exact Chronos attempt, admits only a registered command with its
approved argument prefix, rejects known interpreter/eval escape flags,
canonicalizes the cwd beneath the workspace, and copies only explicitly
allowlisted environment names into a clean process. The host-owned boundary
uses no shell or `PATH` lookup, bounds retained UTF-8 output, kills the process
group on cancellation or owner loss, and reaps before release.

`make qualify-local-agent` launches the actual executable with real local Aegis,
Chronos and Daimon sockets plus the hermetic ACP process. Its two process
journeys prove authorized open and prompt, both a governed client file read and
a governed terminal create through fresh Aegis and Chronos checks, terminal
output through the real process boundary, terminal close, process termination,
durable service reopen, and exact read/terminal event recovery without provider
redispatch. On macOS the
journey additionally selects a digest-bound deny-default Seatbelt profile; the
fixture refuses to proceed unless an attempted workspace mutation is denied.
