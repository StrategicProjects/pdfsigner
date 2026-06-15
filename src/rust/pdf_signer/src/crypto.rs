//! Pure-Rust (RustCrypto) CMS signing and verification.
//!
//! Replaces the OpenSSL backend so the crate can be vendored for a CRAN build
//! with no system OpenSSL dependency. Produces / consumes `adbe.pkcs7.detached`
//! style detached CMS (PKCS#7 SignedData) over an external byte range.

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfo, SignerInfos, SignerIdentifier};

use const_oid::db::rfc5911::{
    ID_AA_SIGNING_CERTIFICATE_V_2, ID_DATA, ID_MESSAGE_DIGEST, ID_SIGNING_TIME,
};
use const_oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION, SECP_256_R_1,
    SECP_384_R_1,
};
use const_oid::db::rfc8410::ID_ED_25519;
use const_oid::ObjectIdentifier;

use der::asn1::{BitString, OctetString, SetOfVec, UtcTime};
use der::{Any, DateTime, Decode, Encode, Sequence};

use rsa::pkcs8::{DecodePrivateKey, PrivateKeyInfo};
use sha2::{Sha384, Sha512};
use signature::{Keypair, Signer};
use spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};

use std::time::SystemTime;
use x509_cert::attr::Attribute;
use x509_cert::time::Time;

/// id-aa-timeStampToken (RFC 3161), not present in the const-oid database.
const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// `ESSCertIDv2` with the SHA-256 default hash algorithm and `issuerSerial`
/// omitted (both optional), leaving just the certificate hash.
#[derive(Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
}

/// `SigningCertificateV2` (RFC 5035) — binds the signer certificate to the
/// signature, the key requirement that turns a basic CMS into CAdES/PAdES.
#[derive(Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

use p12_keystore::KeyStore;

use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
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

fn sha384_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA_384,
        parameters: None,
    }
}

fn sha512_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA_512,
        parameters: None,
    }
}

/// Adapter so the CMS / X.509 builders (which require
/// `SignatureBitStringEncoding`) can drive an `ed25519-dalek` key.
pub(crate) struct Ed25519Signer(pub(crate) ed25519_dalek::SigningKey);

/// Newtype giving `ed25519::Signature` a `SignatureBitStringEncoding` impl.
pub(crate) struct Ed25519Sig(ed25519::Signature);

impl SignatureBitStringEncoding for Ed25519Sig {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.0.to_bytes())
    }
}
impl Keypair for Ed25519Signer {
    type VerifyingKey = ed25519_dalek::VerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}
impl Signer<Ed25519Sig> for Ed25519Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Ed25519Sig, signature::Error> {
        Ok(Ed25519Sig(self.0.try_sign(msg)?))
    }
}
impl DynSignatureAlgorithmIdentifier for Ed25519Signer {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ID_ED_25519,
            parameters: None,
        })
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

/// Build the `signing-certificate-v2` (ESS) signed attribute over the DER of
/// the signer certificate.
fn signing_certificate_v2_attribute(cert_der: &[u8]) -> Result<Attribute> {
    let hash = Sha256::digest(cert_der);
    let scv2 = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            cert_hash: OctetString::new(hash.to_vec()).map_err(crypto)?,
        }],
    };
    let mut values = SetOfVec::new();
    values
        .insert(Any::encode_from(&scv2).map_err(crypto)?)
        .map_err(crypto)?;
    Ok(Attribute {
        oid: ID_AA_SIGNING_CERTIFICATE_V_2,
        values,
    })
}

/// Produce a detached CMS signature over `data` using the PKCS#12 keystore.
///
/// The signature is CAdES/PAdES-B-B (carries a `signing-certificate-v2`
/// attribute). When `tsa_url` is `Some`, an RFC 3161 signature timestamp is
/// fetched and embedded, yielding PAdES-B-T.
pub(crate) fn cms_sign(
    keystore_p12: &[u8],
    password: &str,
    data: &[u8],
    tsa_url: Option<&str>,
) -> Result<Vec<u8>> {
    // 1. Load key + certificate from the keystore.
    let ks = KeyStore::from_pkcs12(keystore_p12, password).map_err(crypto)?;
    let (_, chain) = ks
        .private_key_chain()
        .ok_or_else(|| Error::Crypto("keystore has no private key chain".into()))?;
    let leaf = chain
        .chain()
        .first()
        .ok_or_else(|| Error::Crypto("keystore has no certificate".into()))?;
    let cert_der = leaf.as_der().to_vec();
    let cert = Certificate::from_der(&cert_der).map_err(crypto)?;

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    });
    // Embed the whole chain (so intermediates are available for path building).
    let cert_ders: Vec<Vec<u8>> = chain.chain().iter().map(|c| c.as_der().to_vec()).collect();
    let key_der = chain.key();

    // 2. Build the SignedData using the algorithm that matches the key type.
    let content_info = match detect_key_kind(key_der)? {
        KeyKind::Rsa => {
            let sk = SigningKey::<Sha256>::new(RsaPrivateKey::from_pkcs8_der(key_der).map_err(crypto)?);
            build_signed_data::<_, Signature>(
                &sk, sha256_alg(), Sha256::digest(data).as_slice(), sid, &cert_der, &cert_ders,
            )?
        }
        KeyKind::P256 => {
            let sk = p256::ecdsa::SigningKey::from(
                p256::SecretKey::from_pkcs8_der(key_der).map_err(crypto)?,
            );
            build_signed_data::<_, p256::ecdsa::DerSignature>(
                &sk, sha256_alg(), Sha256::digest(data).as_slice(), sid, &cert_der, &cert_ders,
            )?
        }
        KeyKind::P384 => {
            let sk = p384::ecdsa::SigningKey::from(
                p384::SecretKey::from_pkcs8_der(key_der).map_err(crypto)?,
            );
            build_signed_data::<_, p384::ecdsa::DerSignature>(
                &sk, sha384_alg(), Sha384::digest(data).as_slice(), sid, &cert_der, &cert_ders,
            )?
        }
        KeyKind::Ed25519 => {
            let sk = ed25519_dalek::SigningKey::from_pkcs8_der(key_der).map_err(crypto)?;
            // RFC 8419: Ed25519 in CMS uses SHA-512 for the message digest.
            build_signed_data::<_, Ed25519Sig>(
                &Ed25519Signer(sk),
                sha512_alg(),
                Sha512::digest(data).as_slice(),
                sid,
                &cert_der,
                &cert_ders,
            )?
        }
    };

    match tsa_url {
        Some(url) => apply_timestamp(content_info, url),
        None => content_info.to_der().map_err(crypto),
    }
}

/// Supported signer key types.
enum KeyKind {
    Rsa,
    P256,
    P384,
    Ed25519,
}

/// Determine the signing key type from its PKCS#8 algorithm identifier.
fn detect_key_kind(pkcs8_der: &[u8]) -> Result<KeyKind> {
    let pki = PrivateKeyInfo::from_der(pkcs8_der).map_err(crypto)?;
    let oid = pki.algorithm.oid;
    if oid == RSA_ENCRYPTION {
        Ok(KeyKind::Rsa)
    } else if oid == ID_ED_25519 {
        Ok(KeyKind::Ed25519)
    } else if oid == ID_EC_PUBLIC_KEY {
        let curve = pki.algorithm.parameters_oid().map_err(crypto)?;
        if curve == SECP_256_R_1 {
            Ok(KeyKind::P256)
        } else if curve == SECP_384_R_1 {
            Ok(KeyKind::P384)
        } else {
            Err(Error::Crypto(format!("unsupported EC curve: {curve}")))
        }
    } else {
        Err(Error::Crypto(format!("unsupported signing key algorithm: {oid}")))
    }
}

/// Assemble a detached `SignedData` (B-B: with `signing-certificate-v2`) over a
/// pre-computed `data_digest`, generic over the signer and signature types.
fn build_signed_data<S, Sig>(
    signing_key: &S,
    digest_alg: AlgorithmIdentifierOwned,
    data_digest: &[u8],
    sid: SignerIdentifier,
    ess_cert_der: &[u8],
    cert_ders: &[Vec<u8>],
) -> Result<ContentInfo>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<Sig>,
    Sig: SignatureBitStringEncoding,
{
    let encap = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };
    let mut signer_info =
        SignerInfoBuilder::new(signing_key, sid, digest_alg.clone(), &encap, Some(data_digest))
            .map_err(crypto)?;
    signer_info
        .add_signed_attribute(signing_time_attribute()?)
        .map_err(crypto)?;
    signer_info
        .add_signed_attribute(signing_certificate_v2_attribute(ess_cert_der)?)
        .map_err(crypto)?;

    let mut builder = SignedDataBuilder::new(&encap);
    builder.add_digest_algorithm(digest_alg).map_err(crypto)?;
    for der in cert_ders {
        let c = Certificate::from_der(der).map_err(crypto)?;
        builder
            .add_certificate(CertificateChoices::Certificate(c))
            .map_err(crypto)?;
    }
    builder
        .add_signer_info::<S, Sig>(signer_info)
        .map_err(crypto)?
        .build()
        .map_err(crypto)
}

/// Fetch an RFC 3161 timestamp over the signature and embed it as the
/// `id-aa-timeStampToken` unsigned attribute (PAdES-B-T).
fn apply_timestamp(ci: ContentInfo, tsa_url: &str) -> Result<Vec<u8>> {
    let mut sd = ci.content.decode_as::<SignedData>().map_err(crypto)?;

    let mut signers: Vec<SignerInfo> = sd.signer_infos.0.iter().cloned().collect();
    let si = signers
        .get_mut(0)
        .ok_or_else(|| Error::Crypto("no SignerInfo to timestamp".into()))?;

    let token = crate::tsa::request_timestamp(tsa_url, si.signature.as_bytes())?;

    let mut ts_values = SetOfVec::new();
    ts_values
        .insert(Any::encode_from(&token).map_err(crypto)?)
        .map_err(crypto)?;
    let ts_attr = Attribute {
        oid: ID_AA_TIME_STAMP_TOKEN,
        values: ts_values,
    };

    let mut unsigned = si.unsigned_attrs.clone().unwrap_or_default();
    unsigned.insert(ts_attr).map_err(crypto)?;
    si.unsigned_attrs = Some(unsigned);

    sd.signer_infos = SignerInfos(SetOfVec::try_from(signers).map_err(crypto)?);

    let new_ci = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&sd).map_err(crypto)?,
    };
    new_ci.to_der().map_err(crypto)
}

/// Extract the signer certificate (matched by SignerIdentifier) and the full
/// pool of certificates embedded in a signature CMS, for chain validation.
pub(crate) fn signer_certificate_and_pool(
    cms_der: &[u8],
) -> Result<(Certificate, Vec<Certificate>)> {
    let ci = ContentInfo::from_der(cms_der).map_err(crypto)?;
    let sd = ci.content.decode_as::<SignedData>().map_err(crypto)?;
    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| Error::Verification("no SignerInfo present".into()))?;
    let signer = find_signer_cert(&sd, si)?.clone();

    let mut pool = Vec::new();
    if let Some(set) = &sd.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(c) = choice {
                pool.push(c.clone());
            }
        }
    }
    Ok((signer, pool))
}

/// Lightweight check that a `/DocTimeStamp` `/Contents` is a well-formed RFC
/// 3161 token whose message imprint is bound to `data` (the document byte
/// range). Full TSA-signature/chain validation is left for a future B-LT
/// verifier; this confirms structure + binding.
pub(crate) fn verify_doc_timestamp(token_der: &[u8], data: &[u8]) -> Result<()> {
    ContentInfo::from_der(token_der).map_err(crypto)?;
    let imprint = Sha256::digest(data);
    if token_der.windows(imprint.len()).any(|w| w == imprint.as_slice()) {
        Ok(())
    } else {
        Err(Error::Verification(
            "timestamp imprint does not match the document".into(),
        ))
    }
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

    // 1. messageDigest attribute must equal H(data) for the SignerInfo's digest.
    let want = digest_data(si.digest_alg.oid, data)?;
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
        Some(d) if d == want => {}
        Some(_) => return Err(Error::Verification("messageDigest mismatch".into())),
        None => return Err(Error::Verification("no messageDigest attribute".into())),
    }

    // 2. Locate the signer certificate by issuer + serial.
    let cert = find_signer_cert(&sd, si)?;

    // 3. Verify the signer's signature over the DER of the signed attributes,
    //    using RSA or ECDSA according to the certificate's public key.
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki.to_der().map_err(crypto)?;
    let signed_attrs_der = signed_attrs.to_der().map_err(crypto)?;
    let sig_bytes = si.signature.as_bytes();

    let ok = if spki.algorithm.oid == RSA_ENCRYPTION {
        let pub_key = rsa::RsaPublicKey::from_public_key_der(&spki_der).map_err(crypto)?;
        let vk = VerifyingKey::<Sha256>::new(pub_key);
        match Signature::try_from(sig_bytes) {
            Ok(s) => vk.verify(&signed_attrs_der, &s).is_ok(),
            Err(_) => false,
        }
    } else if spki.algorithm.oid == ID_EC_PUBLIC_KEY {
        verify_ecdsa_sig(&spki_der, &signed_attrs_der, sig_bytes)
    } else if spki.algorithm.oid == ID_ED_25519 {
        verify_ed25519_sig(&spki_der, &signed_attrs_der, sig_bytes)
    } else {
        return Err(Error::Verification("unsupported signer key algorithm".into()));
    };
    if !ok {
        return Err(Error::Verification("signature invalid".into()));
    }

    Ok(CmsVerification {
        signer_subject: cert.tbs_certificate.subject.to_string(),
    })
}

/// Hash `data` with the digest named by `oid` (SHA-256/384/512).
fn digest_data(oid: ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>> {
    if oid == ID_SHA_256 {
        Ok(Sha256::digest(data).to_vec())
    } else if oid == ID_SHA_384 {
        Ok(Sha384::digest(data).to_vec())
    } else if oid == ID_SHA_512 {
        Ok(Sha512::digest(data).to_vec())
    } else {
        Err(Error::Verification("unsupported digest algorithm".into()))
    }
}

/// Verify an ECDSA signature (P-256 / P-384, DER `ECDSA-Sig-Value`) over `msg`.
fn verify_ecdsa_sig(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use signature::Verifier as _;
    use spki::DecodePublicKey as _;
    if let (Ok(vk), Ok(s)) = (
        p256::ecdsa::VerifyingKey::from_public_key_der(spki_der),
        p256::ecdsa::DerSignature::try_from(sig),
    ) {
        return vk.verify(msg, &s).is_ok();
    }
    if let (Ok(vk), Ok(s)) = (
        p384::ecdsa::VerifyingKey::from_public_key_der(spki_der),
        p384::ecdsa::DerSignature::try_from(sig),
    ) {
        return vk.verify(msg, &s).is_ok();
    }
    false
}

/// Verify an Ed25519 signature over `msg`.
fn verify_ed25519_sig(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use signature::Verifier as _;
    use spki::DecodePublicKey as _;
    if let (Ok(vk), Ok(s)) = (
        ed25519_dalek::VerifyingKey::from_public_key_der(spki_der),
        ed25519::Signature::from_slice(sig),
    ) {
        return vk.verify(msg, &s).is_ok();
    }
    false
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
