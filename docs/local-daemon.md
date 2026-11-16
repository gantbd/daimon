# Local daemon profile

The selected local boundary is an authenticated, single-owner Unix service. It
is private deployment plumbing, not a public network protocol.

## Invariants

- The daemon creates a new socket path and refuses to adopt an existing entry.
- The socket is published at mode 0600 and removed only if its device and inode
  still match the daemon's original socket.
- The host authenticator derives the principal and opaque authority context from
  the accepted connection before a Daimon session is opened.
- The server-selected session handle is returned in a bounded canonical handshake.
  A different handle in a request is refused before dispatch.
- Frame bytes, context/tools/artifacts, requests per connection and I/O time are
  finite. Clean EOF closes the service session.
- A request write/read failure after client transmission is outcome unknown. A
  server reply-write failure after dispatch is also outcome unknown. Callers
  reconcile by execution identity instead of blindly redispatching.
- The durable service commits an outcome-unknown fence before provider dispatch
  and the exact result before publication. Socket and filesystem reopen therefore
  returns the same result without another provider call.
- Model execution uses a separately tagged frame family and a dedicated model
  socket composition. Its independent output/proposal limits cannot widen the
  legacy artifact protocol, while both endpoints use the same authenticated
  session and inode-safe socket laws.

## Deliberate limits

The crate does not select an operating-system peer credential policy, TLS,
multi-host transport, daemon supervision or provider sandbox. An embedding
executable must provide the `Authenticator`, own lifecycle/signal policy and keep
the socket inside a private directory. The Moira-to-Daimon qualification proves
process exit/reopen after a discarded reply; supervision, signal and cancellation
policy remain embedding responsibilities.
