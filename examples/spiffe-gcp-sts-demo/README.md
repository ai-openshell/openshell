<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SPIFFE to Google STS Demo

This example gives a sandbox Google Cloud access with no stored credential. The
supervisor exchanges its SPIFFE JWT-SVID at Google Security Token Service
(RFC 8693) and injects the federated access token on `*.googleapis.com`.

1. SPIRE signs JWT-SVIDs with `jwt_issuer` set to a public HTTPS OIDC discovery
   URL and an RS256 or ES256 key.
2. A Google Workload Identity Federation pool provider trusts that issuer.
3. IAM grants the sandbox's SPIFFE principal access, for example
   `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/onix-spire/subject/spiffe://example.org/ns/team/agent/app`.

Replace `PROJECT_NUMBER` in `provider-profile.yaml` and set `binaries` to the
programs in your sandbox image that call Google APIs. The profile's network
rule allows only those binaries, so a binary not on the list is denied. Then
import the profile and create a provider with no credentials:

```shell
openshell profile lint -f examples/spiffe-gcp-sts-demo/provider-profile.yaml
openshell profile import -f examples/spiffe-gcp-sts-demo/provider-profile.yaml
openshell provider create --name gcp --type google-cloud-spiffe --runtime-credentials
```

Inside a sandbox with the provider attached, Google SDKs using Application
Default Credentials read a placeholder token from the OpenShell metadata
emulator. The supervisor replaces it with the federated token on Google API
requests. The STS request the supervisor sends is:

```text
POST https://sts.googleapis.com/v1/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
audience=//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/onix-spire/providers/spire
scope=https://www.googleapis.com/auth/cloud-platform
requested_token_type=urn:ietf:params:oauth:token-type:access_token
subject_token_type=urn:ietf:params:oauth:token-type:jwt
subject_token=<JWT-SVID>
```
