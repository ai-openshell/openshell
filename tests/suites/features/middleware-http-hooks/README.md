# Registered middleware HTTP hooks

Run `mise run e2e:middleware-http-hooks` to start a Docker gateway and the
content-guard example and run the suite. The tmachine row
`ubuntu-docker-rootful-middleware-http-hooks/deb` starts and registers the same
example during environment setup. Build its binary with
`nix run .#build-artifacts-test-archives` when preparing inputs locally.

Both environments set `OPENSHELL_TEST_CONTENT_GUARD_REGISTRATION` to the name
registered in the gateway (typically `content-guard-example`). The suite fails
if it is missing. The gateway and supervisor must be able to reach the guard,
and the sandbox must be able to reach an upstream hosted by the test process
at `host.openshell.internal`.
