#!/usr/bin/python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""SPIFFE Workload APIs for an OpenShell test environment.

Serves FetchJWTSVID and FetchJWTBundles twice: for the gateway on a Unix
socket and for supervisors on a TCP address. Each issues RS256 JWT-SVIDs for
one SPIFFE ID, whoever asks: suites test credential isolation with distinct
providers and audiences, not attestation. Both sign with one key, which is
created on first start, and serve its JWKS as the trust domain's bundle. The
JWKS is also written to a file, for tests to verify SVIDs with.

The messages are hand-encoded, so the stub needs only grpcio and
cryptography, not generated code.
"""

import argparse
import base64
import json
import os
import time
from concurrent import futures
from pathlib import Path

import grpc
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY_ID = "openshell-test-key"
SVID_LIFETIME_SECONDS = 3600


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field(number, data):
    """A length-delimited protobuf field."""
    if isinstance(data, str):
        data = data.encode()
    return varint(number << 3 | 2) + varint(len(data)) + data


def read_varint(data, index):
    value = shift = 0
    while True:
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, index


def string_fields(data, number):
    """The values of every length-delimited field `number` in a message."""
    values = []
    index = 0
    while index < len(data):
        key, index = read_varint(data, index)
        wire_type = key & 7
        if wire_type == 0:
            _, index = read_varint(data, index)
        elif wire_type == 1:
            index += 8
        elif wire_type == 2:
            length, index = read_varint(data, index)
            if key >> 3 == number:
                values.append(data[index : index + length].decode())
            index += length
        elif wire_type == 5:
            index += 4
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
    return values


def load_key(path, jwks_path):
    path = Path(path)
    jwks_path = Path(jwks_path)
    if not path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(pem)
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    numbers = key.public_key().public_numbers()
    jwks = json.dumps(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": KEY_ID,
                    "use": "sig",
                    "alg": "RS256",
                    "n": b64url(
                        numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                    ),
                    "e": b64url(
                        numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
                    ),
                }
            ]
        }
    ).encode()
    partial = jwks_path.with_name(f"{jwks_path.name}.partial")
    partial.write_bytes(jwks)
    partial.chmod(0o644)
    partial.replace(jwks_path)
    return key, jwks


class WorkloadApi:
    def __init__(self, key, jwks, issuer, trust_domain, spiffe_id):
        self.key = key
        self.jwks = jwks
        self.issuer = issuer
        self.trust_domain = trust_domain
        self.spiffe_id = spiffe_id

    def jwt_svid(self, audience):
        now = int(time.time())
        header = {"alg": "RS256", "kid": KEY_ID, "typ": "JWT"}
        claims = {
            "iss": self.issuer,
            "sub": self.spiffe_id,
            "aud": audience,
            "iat": now,
            "exp": now + SVID_LIFETIME_SECONDS,
        }
        signing_input = (
            b64url(json.dumps(header).encode())
            + "."
            + b64url(json.dumps(claims).encode())
        )
        signature = self.key.sign(
            signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()
        )
        return signing_input + "." + b64url(signature)

    def fetch_jwt_svid(self, request, _context):
        audience = string_fields(request, 1)
        svid = field(1, self.spiffe_id) + field(2, self.jwt_svid(audience))
        return field(1, svid)

    def fetch_jwt_bundles(self, _request, _context):
        yield field(1, field(1, self.trust_domain) + field(2, self.jwks))

    def handler(self):
        identity = lambda data: data  # noqa: E731
        return grpc.method_handlers_generic_handler(
            "SpiffeWorkloadAPI",
            {
                "FetchJWTSVID": grpc.unary_unary_rpc_method_handler(
                    self.fetch_jwt_svid,
                    request_deserializer=identity,
                    response_serializer=identity,
                ),
                "FetchJWTBundles": grpc.unary_stream_rpc_method_handler(
                    self.fetch_jwt_bundles,
                    request_deserializer=identity,
                    response_serializer=identity,
                ),
            },
        )


def serve(api, address):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    server.add_generic_rpc_handlers((api.handler(),))
    if server.add_insecure_port(address) == 0:
        raise SystemExit(f"cannot listen on {address}")
    server.start()
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--key", required=True, help="signing key, created if missing")
    parser.add_argument("--jwks", required=True, help="where to write the bundle")
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--trust-domain", required=True)
    parser.add_argument("--gateway-socket", required=True)
    parser.add_argument("--gateway-id", required=True)
    parser.add_argument("--supervisor-address", required=True, help="host:port")
    parser.add_argument("--supervisor-id", required=True)
    args = parser.parse_args()

    key, jwks = load_key(args.key, args.jwks)
    Path(args.gateway_socket).unlink(missing_ok=True)
    servers = [
        serve(
            WorkloadApi(key, jwks, args.issuer, args.trust_domain, args.gateway_id),
            f"unix:{args.gateway_socket}",
        ),
        serve(
            WorkloadApi(key, jwks, args.issuer, args.trust_domain, args.supervisor_id),
            args.supervisor_address,
        ),
    ]
    # The gateway may run as another user.
    Path(args.gateway_socket).chmod(0o777)
    print(f"serving {args.gateway_socket} and {args.supervisor_address}", flush=True)
    for server in servers:
        server.wait_for_termination()


if __name__ == "__main__":
    main()
