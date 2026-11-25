// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Requests to sandbox services that the gateway exposes.
//!
//! A service URL names the sandbox and service in its host, such as
//! `http://default--my-sandbox.openshell.localhost:8080/`. The gateway routes
//! service requests by their Host header on its own listener, so testkit
//! connects to the gateway's endpoint and sends the service URL's host as the
//! Host header. The machine that runs the tests doesn't need to resolve
//! service hosts.
//!
//! The request keeps the service URL's scheme. A gateway listening on
//! loopback reports `http` service URLs and accepts plaintext service
//! requests on its TLS listener. Over TLS, testkit verifies the gateway's
//! certificate against the endpoint's host. A registered mTLS gateway's CA
//! verifies it and testkit presents its client certificate; otherwise the
//! system roots verify it, as the SDK does.

use std::path::Path;
use std::time::Duration;

use reqwest::Url;
use reqwest::header::HOST;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::context::Context;
use crate::error::{Error, Result, ResultExt as _};
use crate::gateway::Gateway;

/// How long one service request may take.
pub const SERVICE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The response to a service request.
#[derive(Debug)]
pub struct ServiceResponse {
    pub status: u16,
    pub body: String,
}

impl Context {
    /// Send `GET service_url` with `headers` through the test's gateway and
    /// return the response, whatever its status. See [the module
    /// docs](crate::service) for how the request reaches the gateway.
    pub async fn service_get(
        &self,
        service_url: &str,
        headers: &[(&str, &str)],
    ) -> Result<ServiceResponse> {
        let cli = self.cli_handle();
        let request = ServiceRequest::new(cli.gateway(), service_url)?;
        let mut builder = client(cli.gateway(), &request)?
            .get(request.target)
            .header(HOST, &request.host);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let what = format!("GET {service_url} through {}", cli.gateway().endpoint);
        let response = builder.send().await.context(&what)?;
        let status = response.status().as_u16();
        let body = response.text().await.context(&what)?;
        Ok(ServiceResponse { status, body })
    }
}

/// Where a service request goes, and the Host header that selects the
/// service.
#[derive(Debug, PartialEq, Eq)]
struct ServiceRequest {
    target: Url,
    host: String,
}

impl ServiceRequest {
    fn new(gateway: &Gateway, service_url: &str) -> Result<Self> {
        let service = parse(service_url, "service URL")?;
        let endpoint = parse(&gateway.endpoint, "gateway endpoint")?;
        let service_host = service
            .host_str()
            .ok_or_else(|| Error::msg(format!("service URL {service_url} has no host")))?;
        let host = match service.port() {
            Some(port) => format!("{service_host}:{port}"),
            None => service_host.to_string(),
        };
        let mut target = service.clone();
        target
            .set_host(endpoint.host_str())
            .map_err(Error::from_display)
            .context(format!("send {service_url} to {}", gateway.endpoint))?;
        target
            .set_port(endpoint.port_or_known_default())
            .map_err(|()| Error::msg(format!("send {service_url} to {}", gateway.endpoint)))?;
        Ok(Self { target, host })
    }
}

fn parse(url: &str, what: &str) -> Result<Url> {
    Url::parse(url)
        .map_err(Error::from_display)
        .context(format!("parse {what} {url}"))
}

/// An HTTP client for `request`. With a registered mTLS gateway it trusts the
/// gateway's CA and presents its client certificate. Otherwise an `https`
/// request trusts the system roots, and a plaintext one needs none.
fn client(gateway: &Gateway, request: &ServiceRequest) -> Result<reqwest::Client> {
    let builder = openshell_crypto::tls::client_builder();
    let tls = match gateway.mtls_dir() {
        Some(dir) => {
            let mut roots = RootCertStore::empty();
            for certificate in certificates(&dir.join("ca.crt"))? {
                roots
                    .add(certificate)
                    .map_err(Error::from_display)
                    .context("trust the gateway CA")?;
            }
            builder
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    certificates(&dir.join("tls.crt"))?,
                    private_key(&dir.join("tls.key"))?,
                )
                .map_err(Error::from_display)
                .context("use the gateway client certificate")?
        }
        None if request.target.scheme() == "https" => builder
            .with_root_certificates(system_roots()?)
            .with_no_client_auth(),
        None => builder
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    };
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(SERVICE_REQUEST_TIMEOUT)
        .build()
        .context("build the service HTTP client")
}

fn system_roots() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        return Err(Error::msg(
            "no system root certificates to verify the https gateway, which has no registered mTLS bundle",
        ));
    }
    Ok(roots)
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect)
        .map_err(Error::from_display)
        .context(format!("read {}", path.display()))
}

fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(Error::from_display)
        .context(format!("read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{ServiceRequest, client};
    use crate::gateway::Gateway;

    /// reqwest accepts the rustls configuration only as a plain
    /// `ClientConfig`; anything else fails when the client is built.
    #[test]
    fn client_accepts_the_tls_configuration() {
        let gateway =
            Gateway::from_endpoint("http://127.0.0.1:8080".to_string(), "default".to_string());
        let request = ServiceRequest::new(&gateway, "http://default--sb.openshell.localhost:8080/")
            .expect("service request");
        client(&gateway, &request).expect("service HTTP client");
    }

    /// An `https` gateway without a registered mTLS bundle is verified
    /// against the system roots, as the SDK does. Without any, the client
    /// fails up front instead of failing every handshake.
    #[test]
    fn https_without_mtls_trusts_the_system_roots() {
        let gateway = Gateway::from_endpoint(
            "https://gateway.example:8443".to_string(),
            "default".to_string(),
        );
        let request = ServiceRequest::new(&gateway, "https://default--sb.gateway.example/")
            .expect("service request");
        match super::system_roots() {
            Ok(_) => {
                client(&gateway, &request).expect("service HTTP client");
            }
            Err(error) => {
                let message = client(&gateway, &request)
                    .expect_err("no roots")
                    .to_string();
                assert!(message.contains("no system root certificates"), "{message}");
                assert!(error.to_string().contains("no system root certificates"));
            }
        }
    }

    fn request(endpoint: &str, service_url: &str) -> ServiceRequest {
        let gateway = Gateway::from_endpoint(endpoint.to_string(), "default".to_string());
        ServiceRequest::new(&gateway, service_url).expect("service request")
    }

    /// A loopback gateway with TLS reports `http` service URLs; the request
    /// goes to the gateway's address in plaintext, with the service as Host.
    #[test]
    fn plaintext_service_on_a_tls_gateway() {
        let request = request(
            "https://127.0.0.1:17670",
            "http://default--sb.openshell.localhost:17670/path?q=1",
        );
        assert_eq!(request.target.as_str(), "http://127.0.0.1:17670/path?q=1");
        assert_eq!(request.host, "default--sb.openshell.localhost:17670");
    }

    /// The request goes to the gateway's port even when the service URL
    /// names another one, such as the gateway's port inside a cluster.
    #[test]
    fn service_port_differs_from_the_endpoint() {
        let request = request(
            "https://openshell.openshell.svc.cluster.local:8443",
            "https://default--sb--web.openshell.localhost/",
        );
        assert_eq!(
            request.target.as_str(),
            "https://openshell.openshell.svc.cluster.local:8443/"
        );
        assert_eq!(request.host, "default--sb--web.openshell.localhost");
    }
}
