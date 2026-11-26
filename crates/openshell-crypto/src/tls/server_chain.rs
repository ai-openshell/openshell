// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use rustls::{
    CertificateError, Error, RootCertStore,
    client::verify_server_cert_signed_by_trust_anchor,
    pki_types::{CertificateDer, UnixTime},
    server::ParsedCertificate,
};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate};

/// Check whether a server certificate chain can replace the active one.
///
/// Check the validity dates and verify the path to the last supplied issuer.
/// The active chain can reveal an omitted intermediate in a replacement with a
/// shorter path. Trust still belongs to the client. If the active chain cannot
/// identify an issuer, the issuer could be a client trust root or an omitted
/// intermediate.
pub fn check_server_chain_replacement(
    candidate: &[CertificateDer<'_>],
    active: &[CertificateDer<'_>],
) -> Result<(), Error> {
    let (leaf, authorities) = candidate
        .split_first()
        .ok_or(Error::NoCertificatesPresented)?;
    let leaf_details =
        parse(leaf).ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let leaf = ParsedCertificate::try_from(leaf)?;
    let algorithms = super::signature_verification_algorithms();
    let now = UnixTime::now();
    check_validity(&leaf_details, now)?;
    if leaf_details.is_ca() {
        return Err(Error::InvalidCertificate(CertificateError::InvalidPurpose));
    }
    check_server_usage(&leaf_details)?;

    let tail = if let Some((terminal, intermediates)) = authorities.split_last() {
        let mut parsed = RootCertStore::empty();
        for authority in intermediates {
            parsed.add(CertificateDer::from(authority.as_ref()))?;
        }
        let terminal_details =
            parse(terminal).ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if terminal_details.subject() != terminal_details.issuer() {
            // A client may use the terminal as an intermediate, where it must be a CA.
            if !terminal_details.is_ca() {
                return Err(Error::InvalidCertificate(CertificateError::InvalidPurpose));
            }
            check_validity(&terminal_details, now)?;
            check_server_usage(&terminal_details)?;
        }
        let roots = anchor(terminal)?;
        verify_server_cert_signed_by_trust_anchor(
            &leaf,
            &roots,
            intermediates,
            now,
            algorithms.all,
        )?;
        terminal_details
    } else {
        leaf_details
    };

    if tail.subject() == tail.issuer() {
        return Ok(());
    }
    for authority in active
        .iter()
        .skip(1)
        .filter(|cert| !authorities.contains(cert))
    {
        let Some(known) = parse(authority) else {
            continue;
        };
        let self_issued = known.subject() == known.issuer();
        let matches_tail_issuer = known.subject() == tail.issuer();
        if self_issued || !matches_tail_issuer {
            continue;
        }
        let Ok(roots) = anchor(authority) else {
            continue;
        };
        if verify_server_cert_signed_by_trust_anchor(
            &leaf,
            &roots,
            authorities,
            now,
            algorithms.all,
        )
        .is_ok()
        {
            return Err(Error::InvalidCertificate(CertificateError::UnknownIssuer));
        }
    }
    Ok(())
}

fn anchor(certificate: &CertificateDer<'_>) -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(certificate.as_ref()))?;
    Ok(roots)
}

fn parse<'a>(certificate: &'a CertificateDer<'_>) -> Option<X509Certificate<'a>> {
    let (remaining, parsed) = parse_x509_certificate(certificate.as_ref()).ok()?;
    remaining.is_empty().then_some(parsed)
}

fn check_validity(certificate: &X509Certificate<'_>, now: UnixTime) -> Result<(), Error> {
    let now = i128::from(now.as_secs());
    let validity = certificate.validity();
    if now < i128::from(validity.not_before.timestamp()) {
        return Err(Error::InvalidCertificate(CertificateError::NotValidYet));
    }
    if now > i128::from(validity.not_after.timestamp()) {
        return Err(Error::InvalidCertificate(CertificateError::Expired));
    }
    Ok(())
}

fn check_server_usage(certificate: &X509Certificate<'_>) -> Result<(), Error> {
    if certificate
        .extended_key_usage()
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?
        .is_some_and(|usage| !usage.value.server_auth)
    {
        return Err(Error::InvalidCertificate(CertificateError::InvalidPurpose));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki;
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa};

    #[test]
    fn leaf_only_reload_requires_valid_tls_server_leaf() {
        let key = pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(vec!["app.example.com".into()]).unwrap();
        let unrestricted = pki::self_signed(params.clone(), &key).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_only = pki::self_signed(params.clone(), &key).unwrap();
        params.extended_key_usages.clear();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = pki::self_signed(params, &key).unwrap();

        let active = std::slice::from_ref(unrestricted.der());
        assert!(check_server_chain_replacement(active, active).is_ok());
        for certificate in [client_only, ca] {
            assert_eq!(
                check_server_chain_replacement(std::slice::from_ref(certificate.der()), active),
                Err(Error::InvalidCertificate(CertificateError::InvalidPurpose))
            );
        }
    }
}
