//! Certificate-chain validation against a trust store.
//!
//! Builds a path from a leaf certificate up to a trusted root, verifying each
//! link's signature and validity window. Intended for validating a signer
//! certificate against the **ICP-Brasil** roots (load them with
//! [`TrustStore::from_pem`]), but works with any root set.
//!
//! Scope: RSA PKCS#1 v1.5 with SHA-256/384/512 (the ICP-Brasil norm). ECDSA and
//! SHA-1 links are treated as unverifiable. No name-constraint / policy
//! processing and no revocation checking here (CRLs live in the DSS).

use std::time::SystemTime;

use const_oid::db::rfc5912::{
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier;
use spki::DecodePublicKey;
use x509_cert::Certificate;

use crate::error::Error;
use crate::Result;

const MAX_DEPTH: usize = 10;

/// A set of trusted root certificates (e.g. the ICP-Brasil AC Raiz set).
#[derive(Clone, Default)]
pub struct TrustStore {
    roots: Vec<Certificate>,
}

impl TrustStore {
    /// An empty store (no chain validation will succeed).
    pub fn new() -> Self {
        Self::default()
    }

    /// Load trusted roots from one or more concatenated PEM certificates.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let roots = Certificate::load_pem_chain(pem).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self { roots })
    }

    /// Load trusted roots from DER certificate blobs.
    pub fn from_ders<I: IntoIterator<Item = Vec<u8>>>(ders: I) -> Result<Self> {
        let mut roots = Vec::new();
        for der in ders {
            roots.push(
                Certificate::from_der(&der).map_err(|e| Error::Crypto(e.to_string()))?,
            );
        }
        Ok(Self { roots })
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }
}

/// Outcome of building/validating a certificate path.
#[derive(Debug, Clone)]
pub(crate) struct ChainResult {
    pub trusted: bool,
    pub detail: String,
}

/// Validate that `leaf` chains to a trusted root, using `pool` (e.g. the certs
/// embedded in the CMS) as candidate intermediates, at time `at`.
pub(crate) fn verify_chain(
    leaf: &Certificate,
    pool: &[Certificate],
    store: &TrustStore,
    at: SystemTime,
) -> ChainResult {
    let at = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut current = leaf.clone();
    for _ in 0..MAX_DEPTH {
        if !valid_at(&current, at) {
            return ChainResult {
                trusted: false,
                detail: "a certificate in the path is expired or not yet valid".into(),
            };
        }
        // Signer certificate is itself a trusted root.
        if store.roots.iter().any(|r| same_cert(r, &current)) {
            return ChainResult {
                trusted: true,
                detail: "certificate is a trusted root".into(),
            };
        }
        // Directly issued by a trusted root.
        if let Some(root) = store.roots.iter().find(|r| issued_by(&current, r)) {
            if !valid_at(root, at) {
                return ChainResult {
                    trusted: false,
                    detail: "trusted root is expired".into(),
                };
            }
            return ChainResult {
                trusted: true,
                detail: format!("chains to trusted root ({})", dn(root)),
            };
        }
        // Climb one intermediate from the pool.
        match pool
            .iter()
            .find(|c| !same_cert(c, &current) && issued_by(&current, c))
        {
            Some(next) => current = next.clone(),
            None => {
                return ChainResult {
                    trusted: false,
                    detail: "could not build a path to a trusted root".into(),
                }
            }
        }
    }
    ChainResult {
        trusted: false,
        detail: "certificate path too long".into(),
    }
}

/// `child` is issued by `issuer`: issuer/subject names match and the issuer's
/// public key verifies the child's signature.
fn issued_by(child: &Certificate, issuer: &Certificate) -> bool {
    let child_issuer = child.tbs_certificate.issuer.to_der().ok();
    let issuer_subject = issuer.tbs_certificate.subject.to_der().ok();
    if child_issuer.is_none() || child_issuer != issuer_subject {
        return false;
    }
    verify_cert_signature(child, issuer)
}

fn verify_cert_signature(child: &Certificate, issuer: &Certificate) -> bool {
    let Ok(tbs) = child.tbs_certificate.to_der() else {
        return false;
    };
    let Some(sig) = child.signature.as_bytes() else {
        return false;
    };
    let Ok(spki) = issuer.tbs_certificate.subject_public_key_info.to_der() else {
        return false;
    };
    let Ok(pubkey) = RsaPublicKey::from_public_key_der(&spki) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig) else {
        return false;
    };
    let oid = child.signature_algorithm.oid;
    if oid == SHA_256_WITH_RSA_ENCRYPTION {
        VerifyingKey::<Sha256>::new(pubkey).verify(&tbs, &signature).is_ok()
    } else if oid == SHA_384_WITH_RSA_ENCRYPTION {
        VerifyingKey::<Sha384>::new(pubkey).verify(&tbs, &signature).is_ok()
    } else if oid == SHA_512_WITH_RSA_ENCRYPTION {
        VerifyingKey::<Sha512>::new(pubkey).verify(&tbs, &signature).is_ok()
    } else {
        false // unsupported algorithm (e.g. ECDSA, SHA-1)
    }
}

fn valid_at(cert: &Certificate, at: i64) -> bool {
    let nb = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs() as i64;
    let na = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;
    at >= nb && at <= na
}

fn same_cert(a: &Certificate, b: &Certificate) -> bool {
    match (a.to_der(), b.to_der()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn dn(cert: &Certificate) -> String {
    cert.tbs_certificate.subject.to_string()
}
