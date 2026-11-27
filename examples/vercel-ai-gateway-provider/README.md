# Vercel AI Gateway in an OpenShell sandbox

This example runs [fx](https://github.com/vercel-labs/fx) in an OpenShell
sandbox with the Vercel AI Gateway. The profile in `vercel-ai-gateway.yaml`
lets OpenShell resolve `AI_GATEWAY_API_KEY` as a bearer token only at
`ai-gateway.vercel.sh` and only for the fx binary. Inside the sandbox,
`AI_GATEWAY_API_KEY` holds a placeholder, and no environment variable holds
the real key.

OpenShell does not load the profile on its own. Import it into the gateway
before you create the provider.

## Prerequisites

- A running OpenShell gateway with the Docker runtime
- `openshell` on the host
- A Vercel AI Gateway API key in `AI_GATEWAY_API_KEY`
- An image with fx installed

Run the following commands from the example directory:

```shell
cd examples/vercel-ai-gateway-provider
```

## 1. Import the provider profile

```shell
openshell provider profile lint -f vercel-ai-gateway.yaml
```

```shell
openshell provider profile import -f vercel-ai-gateway.yaml --global
```

Without `--global`, the import goes into the current workspace.

## 2. Create the provider

```shell
openshell provider create --name vercel-ai-gateway --type vercel-ai-gateway --from-existing
```

## 3. Run the smoke test

```shell
openshell sandbox create --provider vercel-ai-gateway --from <fx-image> -- \
  fx ask 'reply with OK'
```

fx replies `OK`.

## Notes

### Binaries

The profile lets only `/usr/local/bin/fx` and `/sandbox/.local/bin/fx` reach
its endpoint. The fx installer writes to `~/.local/bin`, so a profile that
names only `/usr/local/bin/fx` matches nothing in an image built with it. For
another layout, copy the profile and edit `binaries` rather than widening it.

### Credential scope

OpenShell resolves `AI_GATEWAY_API_KEY` only for `ai-gateway.vercel.sh`. The
key works for any model the gateway serves, and the profile cannot restrict
which of them fx uses.

### Not covered

The profile does not cover `fx login`, fx update checks or MCP servers. Those
hosts stay blocked until you add them to your copy.
