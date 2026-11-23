# openshell-driver-sdk

Shared helpers for the compute drivers the gateway launches.

The gateway starts a driver as `openshell-driver-<name> serve` with only its
socket path, the gateway's process ID, and the log level, then configures it
with the `Configure` RPC from `openshell-driver-launch`. This crate holds what
drivers share on top of that protocol:

- `launch`: applies `Configure` telemetry to the driver's supervisor OTLP
  settings and enables the driver's own trace export.
- `network_trust`: loads and re-verifies the gateway's staged network trust
  artifact from its path, digest, and certificate count.
- `parent`: stops the driver when the gateway exits.
- `probe` and `preflight`: the JSON results of those subcommands.

## Subcommands

`probe` and `preflight` print one bounded JSON object on stdout; the result
types are in `probe` and `preflight`. `probe` reports whether the driver is
usable on this host, takes no configuration, and the gateway gives it five
seconds and 4 KiB. `preflight` reads a protobuf-encoded `ConfigureRequest` from stdin and
validates it without starting the driver and gets ten seconds and 16 KiB. The gateway treats
a failure, a timeout, or oversized output as "not available" or a failed
preflight.
