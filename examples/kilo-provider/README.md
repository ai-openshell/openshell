# Kilo in an OpenShell sandbox

This example runs the Kilo CLI in an OpenShell sandbox with the Kilo Gateway.
The provider profile in `kilo.yaml` lets OpenShell resolve `KILO_API_KEY` as a
bearer token only at the endpoints it lists and only for `/usr/local/bin/kilo`.
Inside the sandbox, `KILO_API_KEY` holds a placeholder that OpenShell resolves
at those endpoints, and no environment variable holds the real key.

OpenShell does not load the profile on its own. Import it into the gateway
before you create the provider.

## Prerequisites

- A running OpenShell gateway with the Docker runtime
- `openshell` on the host
- A Kilo Gateway API key in `KILO_API_KEY`

Run the following commands from the example directory:

```shell
cd examples/kilo-provider
```

## 1. Import the provider profile

Lint the profile, then import it at platform scope:

```shell
openshell provider profile lint -f kilo.yaml
```

```shell
openshell provider profile import -f kilo.yaml --global
```

Without `--global`, the import goes into the current workspace.

## 2. Create the provider

Create a provider named `kilo` from the `KILO_API_KEY` variable in your shell:

```shell
openshell provider create --name kilo --type kilo --from-existing
```

## 3. Run the smoke test

```shell
openshell sandbox create --provider kilo \
  --from ghcr.io/kilo-org/kilocode:latest-openshell -- \
  kilo run --model kilo/nvidia/nemotron-3.5-lightning:free 'reply with OK'
```

Kilo replies `OK`. The image is the OpenShell variant of the published Kilo
image, and it keeps Kilo's own sandbox off, as the notes below explain.

## Notes

### Binaries

The profile lets only `/usr/local/bin/kilo` reach its endpoints. Kilo lives at
that path in `ghcr.io/kilo-org/kilocode` and in its OpenShell variant
`ghcr.io/kilo-org/kilocode:latest-openshell`. The `binaries` list is the
least-privilege control that decides which processes may reach the endpoints,
so for another image, copy the profile and edit it to name the paths in that
image. Add curl or an SDK interpreter if the workload calls the API another way.

### Credential scope

OpenShell resolves `KILO_API_KEY` only for the endpoints in the profile. Kilo
also sends the key to `ingest.kilosessions.ai` for cloud session upload and to
`events.kiloapps.io` for its presence service, and the profile leaves both
hosts blocked. The Kilo Gateway serves many upstream models with one key, and
the profile cannot restrict which of them Kilo uses.

### Endpoints

The profile allows three hosts, all read-write with L7 enforcement:

| Host | Used for |
| --- | --- |
| `api.kilo.ai` | Account lookups |
| `ai-gateway.kilo.ai` | Inference and the gateway's model list |
| `us.i.posthog.com` | The CLI's telemetry |

Kilo sends its telemetry with PostHog's own project key and does not include
`KILO_API_KEY`, so allowing `us.i.posthog.com` exposes no credential. Remove
that endpoint from your copy if your policy forbids the traffic. `models.dev`
stays blocked, and Kilo falls back to the model catalog bundled in its binary.

### Kilo's own sandbox

Kilo's sandbox uses bubblewrap, which cannot create its namespaces inside an
OpenShell sandbox. When a project's `kilo.jsonc` turns it on, every tool call
fails, and `kilo run` can still exit 0.

The `-openshell` image sets `{"sandbox": {"enabled": false}}` in
`/etc/kilo/kilo.json`, which Kilo loads after project configuration, so a
project cannot override it. Its environment also sets
`KILO_DISABLE_MODELS_FETCH=1`, `KILO_DISABLE_SESSION_INGEST=1` and
`KILO_DISABLE_PRESENCE=1`, which stop Kilo from trying the blocked hosts.
OpenShell still confines Kilo and every tool it runs.

### Image environment

The image's environment reaches the sandbox's main command only, so start Kilo
as that command, as the smoke test does. A process started with
`openshell sandbox exec` does not get those variables. To reach every process,
pass them with `--env` on `openshell sandbox create`.

### Other images

With another image, add the same `/etc/kilo/kilo.json` and variables yourself.
`KILO_TELEMETRY_LEVEL=off` stops Kilo's telemetry.
