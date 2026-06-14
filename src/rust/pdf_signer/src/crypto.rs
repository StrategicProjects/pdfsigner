//! Pure-Rust (RustCrypto) CMS signing and verification.
//!
//! Replaces the OpenSSL backend so the crate can be vendored for a CRAN build
//! with no system OpenSSL dependency. Produces / consumes `adbe.pkcs7.detached`
//! style detached CMS (PKCS#7 SignedData) over an external byte range.

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};

use const_oid::db::rfc5911::{ID_DATA, ID_MESSAGE_DIGEST, ID_SIGNING_TIME};
use const_oid::db::rfc5912::ID_SHA_256;

use der::asn1::{OctetString, SetOfVec, UtcTime};
use der::{Any, DateTime, Decode, Encode};

use std::time::SystemTime;
use x509_cert::attr::Attribute;
use x509_cert::time::Time;

use p12_keystore::KeyStore;

use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

use sha2::{Digest, Sha256};
use signature::Verifier;
use spki::{AlgorithmIdentifierOwned, DecodePublicKey};
use x509_cert::Certificate;

use crate::error::Error;
use crate::Result;

fn crypto<E: std::fmt::Display>(e: E) -> Error {
    Error::Crypto(e.to_string())
}

/// Outcome of a successful verification.
pub(crate) struct CmsVerification {
    /// Subject Distinguished Name of the signing certificate.
    pub signer_subject: String,
}

fn sha256_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    }
}

/// Build a CMS `signingTime` signed attribute from the current system time.
/// Without it, some viewers (e.g. Poppler's `pdfsig`) report the epoch.
fn signing_time_attribute() -> Result<Attribute> {
    let unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(crypto)?;
    let dt = DateTime::from_unix_duration(unix).map_err(crypto)?;
    let time = Time::UtcTime(UtcTime::from_date_time(dt).map_err(crypto)?);
    let mut values = SetOfVec::new();
    values
        .insert(Any::encode_from(&time).map_err(crypto)?)
        .map_err(crypto)?;
    Ok(Attribute {
        oid: ID_SIGNING_TIME,
        values,
    })
}

/// Produce a detached CMS signature over `data` using the PKCS#12 keystore.
pub(crate) fn cms_sign(keystore_p12: &[u8], password: &str, data: &[u8]) -> Result<Vec<u8>> {
    // 1. Load key + certificate from the keystore.
    let ks = KeyStore::from_pkcs12(keystore_p12, password).map_err(crypto)?;
    let (_, chain) = ks
        .private_key_chain()
        .ok_or_else(|| Error::Crypto("keystore has no private key chain".into()))?;
    let leaf = chain
        .chain()
        .first()
        .ok_or_else(|| Error::Crypto("keystore has no certificate".into()))?;
    let cert = Certificate::from_der(leaf.as_der()).map_err(crypto)?;
    let priv_key = RsaPrivateKey::from_pkcs8_der(chain.key()).map_err(crypto)?;
    let signing_key = SigningKey::<Sha256>::new(priv_key);

    // 2. Detached content: digest is supplied externally, eContent stays empty.
    let digest = Sha256::digest(data);
    let encap = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    });

    let mut signer_info = SignerInfoBuilder::new(
        &signing_key,
        sid,
        sha256_alg(),
        &encap,
        Some(digest.as_slice()),
    )
    .map_err(crypto)?;
    signer_info
        .add_signed_attribute(signing_time_attribute()?)
        .map_err(crypto)?;

    // 3. Assemble the SignedData and DER-encode the ContentInfo wrapper.
    let content_info = SignedDataBuilder::new(&encap)
        .add_digest_algorithm(sha256_alg())
        .map_err(crypto)?
        .add_certificate(CertificateChoices::Certificate(cert))
        .map_err(crypto)?
        .add_signer_info::<SigningKey<Sha256>, Signature>(signer_info)
        .map_err(crypto)?
        .build()
        .map_err(crypto)?;

    content_info.to_der().map_err(crypto)
}

/// Verify a detached CMS `der` (a ContentInfo) against `data`.
///
/// Checks that the embedded `messageDigest` attribute matches `SHA-256(data)`
/// and that the signer's RSA signature over the signed attributes is valid.
/// Does **not** validate the certificate chain / trust (PoC: self-signed).
pub(crate) fn cms_verify(der: &[u8], data: &[u8]) -> Result<CmsVerification> {
    let ci = ContentInfo::from_der(der).map_err(crypto)?;
    let sd = ci.content.decode_as::<SignedData>().map_err(crypto)?;

    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| Error::Verification("no SignerInfo present".into()))?;

    let signed_attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::Verification("signer has no signed attributes".into()))?;

    // 1. messageDigest attribute must equal SHA-256(data).
    let want = Sha256::digest(data);
    let mut found_digest = None;
    for attr in signed_attrs.iter() {
        if attr.oid == ID_MESSAGE_DIGEST {
            let any = attr
                .values
                .iter()
                .next()
                .ok_or_else(|| Error::Verification("empty messageDigest".into()))?;
            let octets = any.decode_as::<OctetString>().map_err(crypto)?;
            found_digest = Some(octets.as_bytes().to_vec());
        }
    }
    match found_digest {
        Some(d) if d == want.as_slice() => {}
        Some(_) => return Err(Error::Verification("messageDigest mismatch".into())),
        None => return Err(Error::Verification("no messageDigest attribute".into())),
    }

    // 2. Locate the signer certificate by issuer + serial.
    let cert = find_signer_cert(&sd, si)?;

    // 3. Verify the RSA signature over the DER of the signed attributes.
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(crypto)?;
    let pub_key = rsa::RsaPublicKey::from_public_key_der(&spki_der).map_err(crypto)?;
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

    let signed_attrs_der = signed_attrs.to_der().map_err(crypto)?;
    let signature = Signature::try_from(si.signature.as_bytes()).map_err(crypto)?;

    verifying_key
        .verify(&signed_attrs_der, &signature)
        .map_err(|e| Error::Verification(format!("signature invalid: {e}")))?;

    Ok(CmsVerification {
        signer_subject: cert.tbs_certificate.subject.to_string(),
    })
}

fn find_signer_cert<'a>(
    sd: &'a SignedData,
    si: &cms::signed_data::SignerInfo,
) -> Result<&'a Certificate> {
    let ias = match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => ias,
        SignerIdentifier::SubjectKeyIdentifier(_) => {
            return Err(Error::Verification(
                "SubjectKeyIdentifier signer id not supported".into(),
            ))
        }
    };
    let certs = sd
        .certificates
        .as_ref()
        .ok_or_else(|| Error::Verification("no certificates embedded".into()))?;

    let want_issuer = ias.issuer.to_der().map_err(crypto)?;
    let want_serial = ias.serial_number.to_der().map_err(crypto)?;

    for choice in certs.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            let issuer = cert.tbs_certificate.issuer.to_der().map_err(crypto)?;
            let serial = cert.tbs_certificate.serial_number.to_der().map_err(crypto)?;
            if issuer == want_issuer && serial == want_serial {
                return Ok(cert);
            }
        }
    }
    Err(Error::Verification(
        "signer certificate not found in CMS".into(),
    ))
}
