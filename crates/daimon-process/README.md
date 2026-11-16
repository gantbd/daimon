# Daimon provider process isolation

`daimon-process` owns the small shared launch-isolation mechanism used by the
ACP and Claude stream-JSON adapters. It does not choose a provider, authorize a
tool, validate a Chronos attempt, or interpret an operating-system policy.

`ProcessIsolationV1::Direct` is explicit unconfined launch. On macOS,
`macos_seatbelt` accepts at most 64 KiB of UTF-8 policy bytes only when their
SHA-256 digest matches deployment configuration. The retained exact bytes are
passed directly to `/usr/bin/sandbox-exec -p`; a mutable policy path is never
given to the child. Debug output exposes the digest but redacts the policy.

The macOS qualification uses a deny-default policy. It proves inherited stdio
still works, file mutation is denied, and both interactive provider adapters can
negotiate through the sandbox. This is mechanism evidence, not certification of
an arbitrary deployment policy. Aegis authority, Chronos attempt currency,
provider permission decisions, and Moira uncertainty/replay laws remain
independent mandatory boundaries. A Linux isolation backend remains open.
