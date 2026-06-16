//! Certificate-chain validation against a trust store.
//!
//! Builds a path from a leaf certificate up to a trusted root, verifying each
//! link's signature and validity window. Intended for validating a signer
//! certificate against the **ICP-Brasil** roots (load them with
//! [`TrustStore::from_pem`]), but works with any root set.
//!
//! Supported signature algorithms: RSA PKCS#1 v1.5 (SHA-256/384/512), ECDSA
//! (P-256/P-384) and Ed25519; SHA-1 links are treated as unverifiable. The path
//! checks basicConstraints/`keyCertSign`, the validity window, RFC 5280 name
//! constraints (§4.2.1.10) and an optional required-policy OID via the
//! [`policy`](crate::policy) engine.
//!
//! Revocation: CRL and OCSP material (collected into the `/DSS`) is
//! authenticated before it is acted on — a CRL must be in scope and signed by
//! the issuing CA and current; an OCSP response must be signed by the issuer or
//! a delegated `id-kp-OCSPSigning` responder and current. Revocation is
//! soft-fail (no usable evidence ⇒ not treated as revoked). Not yet covered:
//! IDP / partitioned CRLs and a hard-fail mode.

use std::time::SystemTime;

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_KP_OCSP_SIGNING,
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::rfc8410::ID_ED_25519;
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier;
use spki::DecodePublicKey;
use std::collections::BTreeSet;

use const_oid::db::rfc5280::ANY_POLICY;
use const_oid::ObjectIdentifier;
use sha1::{Digest as _, Sha1};
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, NameConstraints, SubjectAltName};
use x509_cert::name::{Name, RelativeDistinguishedName};
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, CertId, CertStatus, ResponderId};

use crate::error::Error;
use crate::policy::{process_policies, PolicyInput};
use crate::Result;

const MAX_DEPTH: usize = 10;

/// A set of trusted root certificates (e.g. the ICP-Brasil AC Raiz set), plus
/// optional validation parameters.
#[derive(Clone, Default)]
pub struct TrustStore {
    roots: Vec<Certificate>,
    required_policy: Option<ObjectIdentifier>,
}

impl TrustStore {
    /// An empty store (no chain validation will succeed).
    pub fn new() -> Self {
        Self::default()
    }

    /// Load trusted roots from one or more concatenated PEM certificates.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let roots = Certificate::load_pem_chain(pem).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self {
            roots,
            required_policy: None,
        })
    }

    /// Load trusted roots from DER certificate blobs.
    pub fn from_ders<I: IntoIterator<Item = Vec<u8>>>(ders: I) -> Result<Self> {
        let mut roots = Vec::new();
        for der in ders {
            roots.push(Certificate::from_der(&der).map_err(|e| Error::Crypto(e.to_string()))?);
        }
        Ok(Self {
            roots,
            required_policy: None,
        })
    }

    /// Require that the certificate path asserts a given policy OID (e.g. an
    /// ICP-Brasil policy). Validation then fails unless the leaf — and every
    /// intermediate that carries a policies extension — asserts it (or
    /// `anyPolicy`). This is a practical subset of RFC 5280 §6.1 policy
    /// processing (no policy mapping / `valid_policy_tree`).
    pub fn require_policy(mut self, oid: &str) -> Result<Self> {
        self.required_policy =
            Some(ObjectIdentifier::new(oid).map_err(|e| Error::Crypto(e.to_string()))?);
        Ok(self)
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
/// embedded in the CMS) as candidate intermediates, at time `at`. `crls` are
/// the revocation lists available (e.g. from the document's DSS).
///
/// Enforces, per RFC 5280 (practical subset): each link's signature, validity
/// windows, issuer `basicConstraints` CA flag, `pathLenConstraint`,
/// `keyCertSign` key usage, CRL + OCSP revocation, **name constraints**, and an
/// optional **required policy** OID. Not enforced: the full policy
/// `valid_policy_tree` / policy mapping.
///
/// Revocation is **soft-fail**: a CRL or OCSP response is only acted on once it
/// is authenticated (signed by the issuing CA / an authorized responder), in
/// scope, and current; when no such evidence is available a certificate is not
/// treated as revoked. This avoids a forged or stale list silently flipping the
/// verdict, while not requiring online revocation material to be present.
pub(crate) fn verify_chain(
    leaf: &Certificate,
    pool: &[Certificate],
    store: &TrustStore,
    crls: &[CertificateList],
    ocsps: &[BasicOcspResponse],
    at: SystemTime,
) -> ChainResult {
    let at = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Build [leaf, intermediate..., root] depth-first, backtracking past any
    // candidate issuer that fails its checks so a valid alternative chain — e.g.
    // under cross-signing, duplicate intermediates, or a candidate that trips a
    // constraint — can still be found rather than abandoned.
    let mut path: Vec<Certificate> = vec![leaf.clone()];
    extend_path(&mut path, store, pool, crls, ocsps, at, 0)
}

/// Depth-first certificate-path construction with backtracking. `path` ends at
/// the certificate we are trying to chain upward to a trusted root. Returns the
/// first fully validated [`ChainResult`], else a failure. Each candidate issuer
/// is evaluated independently: a rejected candidate is skipped, not fatal, so a
/// later valid issuer still gets its turn.
#[allow(clippy::too_many_arguments)]
fn extend_path(
    path: &mut Vec<Certificate>,
    store: &TrustStore,
    pool: &[Certificate],
    crls: &[CertificateList],
    ocsps: &[BasicOcspResponse],
    at: i64,
    intermediates: usize,
) -> ChainResult {
    let current = path.last().unwrap().clone();
    if !valid_at(&current, at) {
        return fail("a certificate in the path is expired or not yet valid");
    }
    // The current certificate is itself a trusted anchor.
    if store.roots.iter().any(|r| same_cert(r, &current)) {
        return finalize(path, store, at);
    }
    // The most informative rejection seen so far (a path that reached a root but
    // failed a path-wide check beats the generic "no path" message).
    let mut pending: Option<ChainResult> = None;

    // Try every trusted root that could have issued `current`.
    for root in store.roots.iter().filter(|r| issued_by(&current, r)) {
        if !valid_at(root, at) || revoked(&current, root, crls, ocsps, at) {
            continue;
        }
        path.push(root.clone());
        let result = finalize(path, store, at);
        if result.trusted {
            return result;
        }
        pending.get_or_insert(result);
        path.pop();
    }
    if intermediates >= MAX_DEPTH {
        return pending.unwrap_or_else(|| fail("certificate path too long"));
    }
    // Try every candidate intermediate that could have issued `current`.
    for next in pool.iter() {
        // Skip self and anything already on the path (avoid cycles).
        if same_cert(next, &current) || path.iter().any(|c| same_cert(c, next)) {
            continue;
        }
        if !issued_by(&current, next) {
            continue;
        }
        // Must be a CA whose pathLenConstraint still permits the certificates
        // below it, assert keyCertSign, and not be revoked by its issuer.
        match ca_constraints(next) {
            Some((true, path_len)) if !path_len.is_some_and(|n| (n as usize) < intermediates) => {}
            _ => continue,
        }
        if !permits_cert_sign(next) || revoked(&current, next, crls, ocsps, at) {
            continue;
        }
        path.push(next.clone());
        let result = extend_path(path, store, pool, crls, ocsps, at, intermediates + 1);
        if result.trusted {
            return result;
        }
        pending.get_or_insert(result);
        path.pop();
    }
    pending.unwrap_or_else(|| fail("could not build a path to a trusted root"))
}

/// Run the path-wide checks (name constraints, required policy) once a trusted
/// root has been reached. `path` is `[leaf, intermediate..., root]`.
fn finalize(path: &[Certificate], store: &TrustStore, _at: i64) -> ChainResult {
    if let Err(detail) = check_name_constraints(path) {
        return fail(&detail);
    }
    // RFC 5280 §6.1 policy processing over the path (excluding the anchor).
    let certs: Vec<&Certificate> = path[..path.len().saturating_sub(1)].iter().rev().collect();
    let input = PolicyInput {
        initial_policy_set: match store.required_policy {
            Some(p) => BTreeSet::from([p]),
            None => BTreeSet::from([ANY_POLICY]),
        },
        initial_explicit_policy: store.required_policy.is_some(),
    };
    if let Err(detail) = process_policies(&certs, &input) {
        return fail(&detail);
    }
    let anchor = path.last().expect("non-empty path");
    if path.len() == 1 {
        ok("certificate is a trusted root")
    } else {
        ok(&format!("chains to trusted root ({})", dn(anchor)))
    }
}

// --- RFC 5280 name constraints (§4.2.1.10) -----------------------------------

/// Apply name constraints down the path: each certificate must satisfy the
/// constraints imposed by every CA above it. `path` is `[leaf, ..., root]`.
fn check_name_constraints(path: &[Certificate]) -> std::result::Result<(), String> {
    let mut collected: Vec<NameConstraints> = Vec::new();
    // Walk from the root (trust anchor, unchecked) down to the leaf.
    // `path[0]` is the leaf (the "final certificate" in RFC 5280 §6.1 terms).
    for (i, cert) in path.iter().enumerate().rev() {
        let is_anchor = i == path.len() - 1;
        // RFC 5280 §6.1.3 (b)/(c): a self-issued certificate that is not the
        // final certificate in the path is exempt from the subject name-constraint
        // check (its name is an artefact of a key rollover, not a new identity).
        let exempt_self_issued = i != 0 && crate::policy::is_self_issued(cert);
        if !is_anchor && !exempt_self_issued {
            for name in cert_names(cert) {
                for nc in &collected {
                    if name_excluded(&name, nc) {
                        return Err("subject name excluded by a CA name constraint".into());
                    }
                    if !name_permitted(&name, nc) {
                        return Err("subject name outside a CA's permitted name constraints".into());
                    }
                }
            }
        }
        if let Ok(Some((_, nc))) = cert.tbs_certificate.get::<NameConstraints>() {
            collected.push(nc);
        }
    }
    Ok(())
}

/// The PKCS#9 `emailAddress` attribute OID (`1.2.840.113549.1.9.1`). RFC 5280
/// §4.2.1.10 requires `rfc822Name` constraints to also bind a legacy email
/// address carried in this subject-DN attribute.
const EMAIL_ADDRESS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

/// The constrained names of a certificate: its subject DN (when non-empty), any
/// SANs, and any legacy `emailAddress` attribute in the subject DN promoted to an
/// `rfc822Name` (RFC 5280 §4.2.1.10).
fn cert_names(cert: &Certificate) -> Vec<GeneralName> {
    let mut names = Vec::new();
    if !cert.tbs_certificate.subject.0.is_empty() {
        names.push(GeneralName::DirectoryName(cert.tbs_certificate.subject.clone()));
    }
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == EMAIL_ADDRESS_OID {
                if let Ok(email) = der::asn1::Ia5String::new(&value_string(atv)) {
                    names.push(GeneralName::Rfc822Name(email));
                }
            }
        }
    }
    if let Ok(Some((_, san))) = cert.tbs_certificate.get::<SubjectAltName>() {
        names.extend(san.0.iter().cloned());
    }
    names
}

/// Best-effort decode of an `AttributeTypeAndValue` value into its string content.
fn value_string(atv: &x509_cert::attr::AttributeTypeAndValue) -> String {
    let bytes = atv.value.value();
    String::from_utf8_lossy(bytes).into_owned()
}

fn name_excluded(name: &GeneralName, nc: &NameConstraints) -> bool {
    nc.excluded_subtrees
        .as_ref()
        .is_some_and(|subs| subs.iter().any(|s| within_subtree(name, &s.base) == Some(true)))
}

fn name_permitted(name: &GeneralName, nc: &NameConstraints) -> bool {
    let Some(subs) = &nc.permitted_subtrees else {
        return true; // no permitted constraint
    };
    // Only subtrees of the same type as `name` constrain it.
    let same_type: Vec<_> = subs
        .iter()
        .filter(|s| within_subtree(name, &s.base).is_some())
        .collect();
    if same_type.is_empty() {
        return true; // this type is unconstrained by permittedSubtrees
    }
    same_type
        .iter()
        .any(|s| within_subtree(name, &s.base) == Some(true))
}

/// `Some(true/false)` when `name` and `base` are the same GeneralName type
/// (matched or not), `None` when the types differ (constraint not applicable).
fn within_subtree(name: &GeneralName, base: &GeneralName) -> Option<bool> {
    match (name, base) {
        (GeneralName::DirectoryName(n), GeneralName::DirectoryName(b)) => Some(dn_within(n, b)),
        (GeneralName::DnsName(n), GeneralName::DnsName(b)) => {
            Some(dns_within(n.as_str(), b.as_str()))
        }
        (GeneralName::Rfc822Name(n), GeneralName::Rfc822Name(b)) => {
            Some(email_within(n.as_str(), b.as_str()))
        }
        (GeneralName::IpAddress(n), GeneralName::IpAddress(b)) => {
            Some(ip_within(n.as_bytes(), b.as_bytes()))
        }
        (GeneralName::UniformResourceIdentifier(n), GeneralName::UniformResourceIdentifier(b)) => {
            Some(host_within(uri_host(n.as_str()), b.as_str()))
        }
        _ => None,
    }
}

/// Host-based matching (URI/email): an exact host unless the base begins with a
/// period, which then matches subdomains only (not the bare domain).
fn host_within(host: &str, base: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let b = base.to_ascii_lowercase();
    match b.strip_prefix('.') {
        Some(domain) => h.ends_with(&format!(".{domain}")),
        None => h == b,
    }
}

/// A DN is within a base subtree if the base RDN sequence is a prefix of it,
/// comparing RDNs case-insensitively and ignoring the DirectoryString encoding
/// (PrintableString vs UTF8String) — a practical subset of RFC 5280 §7.1.
fn dn_within(name: &Name, base: &Name) -> bool {
    if base.0.len() > name.0.len() {
        return false;
    }
    base.0
        .iter()
        .zip(name.0.iter())
        .all(|(b, n)| rdn_key(b) == rdn_key(n))
}

/// Normalize an RDN to a set of `(attribute oid, folded value)` pairs.
fn rdn_key(rdn: &RelativeDistinguishedName) -> BTreeSet<(ObjectIdentifier, String)> {
    rdn.0
        .iter()
        .map(|atv| {
            let folded = String::from_utf8_lossy(atv.value.value())
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            (atv.oid, folded)
        })
        .collect()
}

fn dns_within(name: &str, base: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let b = base.trim_start_matches('.').to_ascii_lowercase();
    if b.is_empty() {
        return true;
    }
    n == b || n.ends_with(&format!(".{b}"))
}

fn email_within(name: &str, base: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let b = base.to_ascii_lowercase();
    if b.contains('@') {
        return n == b; // exact mailbox
    }
    match n.split_once('@') {
        Some((_, host)) => host_within(host, &b),
        None => false,
    }
}

fn ip_within(name: &[u8], base: &[u8]) -> bool {
    // base is address || mask (8 bytes for IPv4, 32 for IPv6).
    if base.len() != name.len() * 2 {
        return false;
    }
    let (net, mask) = base.split_at(name.len());
    name.iter()
        .zip(net)
        .zip(mask)
        .all(|((nb, ab), mb)| (nb & mb) == (ab & mb))
}

fn uri_host(uri: &str) -> &str {
    let after_scheme = uri.split("://").nth(1).unwrap_or(uri);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.split(':').next().unwrap_or(host)
}


/// True if an **authenticated** OCSP response marks `cert` (under `issuer`) as
/// revoked. The response must be signed either by the issuer itself or by a
/// delegated responder it certified (with the `id-kp-OCSPSigning` EKU), and the
/// matching single response must be current. Unauthenticated or stale responses
/// are ignored (soft-fail, see [`revoked`]).
fn ocsp_revoked(
    cert: &Certificate,
    issuer: &Certificate,
    ocsps: &[BasicOcspResponse],
    at: i64,
) -> bool {
    let Ok(want) = CertId::from_issuer::<Sha1>(issuer, cert.tbs_certificate.serial_number.clone())
    else {
        return false;
    };
    for basic in ocsps {
        if !ocsp_authentic(basic, issuer) {
            continue;
        }
        for single in basic.tbs_response_data.responses.iter() {
            if cert_id_eq(&single.cert_id, &want)
                && matches!(single.cert_status, CertStatus::Revoked(_))
                && ocsp_single_current(single, at)
            {
                return true;
            }
        }
    }
    false
}

/// Verify that a `BasicOcspResponse` is signed by an authorized responder for
/// `issuer`: either `issuer` directly, or a delegated responder certificate
/// embedded in the response, issued by `issuer` and bearing the OCSP-signing EKU.
fn ocsp_authentic(basic: &BasicOcspResponse, issuer: &Certificate) -> bool {
    let Ok(tbs) = basic.tbs_response_data.to_der() else {
        return false;
    };
    let Some(sig) = basic.signature.as_bytes() else {
        return false;
    };
    let oid = basic.signature_algorithm.oid;
    let rid = &basic.tbs_response_data.responder_id;

    // The issuer signs its own OCSP responses.
    if responder_is(rid, issuer) && verify_with_cert(issuer, &tbs, oid, sig) {
        return true;
    }
    // A delegated responder certified by the issuer.
    if let Some(certs) = &basic.certs {
        for c in certs {
            if responder_is(rid, c)
                && issued_by(c, issuer)
                && has_ocsp_signing_eku(c)
                && verify_with_cert(c, &tbs, oid, sig)
            {
                return true;
            }
        }
    }
    false
}

/// Verify `sig`/`oid` over `tbs` using `cert`'s public key.
fn verify_with_cert(cert: &Certificate, tbs: &[u8], oid: ObjectIdentifier, sig: &[u8]) -> bool {
    match cert.tbs_certificate.subject_public_key_info.to_der() {
        Ok(spki) => verify_signature(tbs, oid, sig, &spki),
        Err(_) => false,
    }
}

/// True if `rid` identifies `cert` (by subject name or by SHA-1 key hash).
fn responder_is(rid: &ResponderId, cert: &Certificate) -> bool {
    match rid {
        ResponderId::ByName(name) => {
            name.to_der().ok() == cert.tbs_certificate.subject.to_der().ok()
        }
        ResponderId::ByKey(key_hash) => {
            match cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
            {
                Some(pk) => Sha1::digest(pk).as_slice() == key_hash.as_bytes(),
                None => false,
            }
        }
    }
}

/// True if `cert` asserts the `id-kp-OCSPSigning` extended key usage.
fn has_ocsp_signing_eku(cert: &Certificate) -> bool {
    matches!(
        cert.tbs_certificate.get::<ExtendedKeyUsage>(),
        Ok(Some((_, eku))) if eku.0.contains(&ID_KP_OCSP_SIGNING)
    )
}

/// True if `at` falls within the single response's `thisUpdate..nextUpdate`.
fn ocsp_single_current(single: &x509_ocsp::SingleResponse, at: i64) -> bool {
    if at < single.this_update.0.to_unix_duration().as_secs() as i64 {
        return false;
    }
    match &single.next_update {
        Some(nu) => at <= nu.0.to_unix_duration().as_secs() as i64,
        None => true,
    }
}

/// Compare two `CertID`s by name hash, key hash and serial (ignoring the hash
/// algorithm's encoding nuances).
fn cert_id_eq(a: &CertId, b: &CertId) -> bool {
    a.issuer_name_hash.as_bytes() == b.issuer_name_hash.as_bytes()
        && a.issuer_key_hash.as_bytes() == b.issuer_key_hash.as_bytes()
        && a.serial_number.to_der().ok() == b.serial_number.to_der().ok()
}

fn ok(detail: &str) -> ChainResult {
    ChainResult {
        trusted: true,
        detail: detail.to_string(),
    }
}

fn fail(detail: &str) -> ChainResult {
    ChainResult {
        trusted: false,
        detail: detail.to_string(),
    }
}

/// `(ca, pathLenConstraint)` from basicConstraints, or `None` if absent.
fn ca_constraints(cert: &Certificate) -> Option<(bool, Option<u8>)> {
    match cert.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((_, bc))) => Some((bc.ca, bc.path_len_constraint)),
        _ => None,
    }
}

/// True if the cert has no keyUsage or asserts keyCertSign.
fn permits_cert_sign(cert: &Certificate) -> bool {
    match cert.tbs_certificate.get::<KeyUsage>() {
        Ok(Some((_, ku))) => ku.key_cert_sign(),
        _ => true, // absent keyUsage = unrestricted
    }
}

/// True if `cert` is revoked by `issuer` according to any authenticated CRL or
/// OCSP response. Revocation is soft-fail: when no usable (authenticated, fresh,
/// in-scope) evidence is available the certificate is *not* treated as revoked.
fn revoked(
    cert: &Certificate,
    issuer: &Certificate,
    crls: &[CertificateList],
    ocsps: &[BasicOcspResponse],
    at: i64,
) -> bool {
    crl_revoked(cert, issuer, crls, at) || ocsp_revoked(cert, issuer, ocsps, at)
}

/// True if an **authenticated** CRL from `issuer` lists `cert` as revoked.
///
/// A CRL is only consulted when it is in scope (issued by this CA), its
/// signature verifies under the CA's key, and it is currently within its
/// `thisUpdate..nextUpdate` window. Unauthenticated, out-of-scope or stale CRLs
/// are ignored rather than trusted (revocation is otherwise soft-fail: absence
/// of usable revocation data does not by itself make a certificate untrusted —
/// see [`verify_chain`]).
fn crl_revoked(cert: &Certificate, issuer: &Certificate, crls: &[CertificateList], at: i64) -> bool {
    let serial = cert.tbs_certificate.serial_number.to_der().ok();
    let ca_subject = issuer.tbs_certificate.subject.to_der().ok();
    for crl in crls {
        // Scope: the CRL must be issued by this CA.
        if crl.tbs_cert_list.issuer.to_der().ok() != ca_subject {
            continue;
        }
        // Authenticity: the CRL must be signed by this CA.
        if !verify_crl_signature(crl, issuer) {
            continue;
        }
        // Freshness: thisUpdate <= at <= nextUpdate (when present).
        if !crl_current(crl, at) {
            continue;
        }
        if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
            if revoked
                .iter()
                .any(|entry| entry.serial_number.to_der().ok() == serial)
            {
                return true;
            }
        }
    }
    false
}

/// Verify a CRL's signature under the issuing CA's public key.
fn verify_crl_signature(crl: &CertificateList, issuer: &Certificate) -> bool {
    let Ok(tbs) = crl.tbs_cert_list.to_der() else {
        return false;
    };
    let Some(sig) = crl.signature.as_bytes() else {
        return false;
    };
    let Ok(spki) = issuer.tbs_certificate.subject_public_key_info.to_der() else {
        return false;
    };
    verify_signature(&tbs, crl.signature_algorithm.oid, sig, &spki)
}

/// True if `at` falls within the CRL's `thisUpdate..nextUpdate` validity window.
/// A CRL without `nextUpdate` is treated as not-yet-stale (only `thisUpdate` is
/// enforced).
fn crl_current(crl: &CertificateList, at: i64) -> bool {
    if at < time_secs(&crl.tbs_cert_list.this_update) {
        return false;
    }
    match &crl.tbs_cert_list.next_update {
        Some(nu) => at <= time_secs(nu),
        None => true,
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
    verify_signature(&tbs, child.signature_algorithm.oid, sig, &spki)
}

/// Verify `sig` over `tbs` under the algorithm `oid`, using the signer's
/// SubjectPublicKeyInfo DER. Shared by certificate, CRL and OCSP verification.
/// SHA-1-based algorithms are treated as unverifiable.
fn verify_signature(tbs: &[u8], oid: ObjectIdentifier, sig: &[u8], signer_spki_der: &[u8]) -> bool {
    if oid == SHA_256_WITH_RSA_ENCRYPTION
        || oid == SHA_384_WITH_RSA_ENCRYPTION
        || oid == SHA_512_WITH_RSA_ENCRYPTION
    {
        let (Ok(pubkey), Ok(signature)) = (
            RsaPublicKey::from_public_key_der(signer_spki_der),
            Signature::try_from(sig),
        ) else {
            return false;
        };
        if oid == SHA_256_WITH_RSA_ENCRYPTION {
            VerifyingKey::<Sha256>::new(pubkey).verify(tbs, &signature).is_ok()
        } else if oid == SHA_384_WITH_RSA_ENCRYPTION {
            VerifyingKey::<Sha384>::new(pubkey).verify(tbs, &signature).is_ok()
        } else {
            VerifyingKey::<Sha512>::new(pubkey).verify(tbs, &signature).is_ok()
        }
    } else if oid == ECDSA_WITH_SHA_256 || oid == ECDSA_WITH_SHA_384 || oid == ECDSA_WITH_SHA_512 {
        verify_ecdsa(signer_spki_der, tbs, sig)
    } else if oid == ID_ED_25519 {
        verify_ed25519(signer_spki_der, tbs, sig)
    } else {
        false // unsupported (e.g. SHA-1)
    }
}

/// Verify an Ed25519 certificate signature.
fn verify_ed25519(spki_der: &[u8], tbs: &[u8], sig: &[u8]) -> bool {
    use signature::Verifier as _;
    use spki::DecodePublicKey as _;
    if let (Ok(vk), Ok(s)) = (
        ed25519_dalek::VerifyingKey::from_public_key_der(spki_der),
        ed25519::Signature::from_slice(sig),
    ) {
        return vk.verify(tbs, &s).is_ok();
    }
    false
}

/// Verify an ECDSA certificate signature over P-256 or P-384 (with the curve's
/// standard hash). The DER signature is `ECDSA-Sig-Value`.
fn verify_ecdsa(spki_der: &[u8], tbs: &[u8], sig: &[u8]) -> bool {
    use signature::Verifier as _;
    if let (Ok(vk), Ok(s)) = (
        p256::ecdsa::VerifyingKey::from_public_key_der(spki_der),
        p256::ecdsa::DerSignature::try_from(sig),
    ) {
        return vk.verify(tbs, &s).is_ok();
    }
    if let (Ok(vk), Ok(s)) = (
        p384::ecdsa::VerifyingKey::from_public_key_der(spki_der),
        p384::ecdsa::DerSignature::try_from(sig),
    ) {
        return vk.verify(tbs, &s).is_ok();
    }
    false
}

fn valid_at(cert: &Certificate, at: i64) -> bool {
    let nb = time_secs(&cert.tbs_certificate.validity.not_before);
    let na = time_secs(&cert.tbs_certificate.validity.not_after);
    at >= nb && at <= na
}

/// An X.509 `Time` (UTCTime / GeneralizedTime) as seconds since the Unix epoch.
fn time_secs(t: &x509_cert::time::Time) -> i64 {
    t.to_unix_duration().as_secs() as i64
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
