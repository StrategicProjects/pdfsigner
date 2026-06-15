//! Verification path: re-derive the signed byte range and validate the CMS.

use std::path::Path;

use std::time::SystemTime;

use der::Decode;
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, OcspResponse};

use crate::crypto::{cms_verify, signer_certificate_and_pool, verify_doc_timestamp};
use crate::error::Error;
use crate::trust::{verify_chain, TrustStore};
use crate::util::{der_total_len, find_sub, hex_decode};
use crate::Result;

/// Validate a certificate path directly (decoupled from PDF signing): does
/// `leaf_der` chain to a trusted root in `roots`, using `pool_ders` as candidate
/// intermediates and `crl_ders` for revocation, at time `at`? Exposed mainly for
/// conformance testing (e.g. NIST PKITS).
pub fn verify_certificate_chain(
    leaf_der: &[u8],
    pool_ders: &[Vec<u8>],
    crl_ders: &[Vec<u8>],
    roots: &TrustStore,
    at: SystemTime,
) -> bool {
    let Ok(leaf) = Certificate::from_der(leaf_der) else {
        return false;
    };
    let pool: Vec<Certificate> = pool_ders
        .iter()
        .filter_map(|d| Certificate::from_der(d).ok())
        .collect();
    let crls = parse_crls(crl_ders);
    verify_chain(&leaf, &pool, roots, &crls, &[], at).trusted
}

/// Parse CRL DER blobs, silently dropping any that fail to decode.
fn parse_crls(ders: &[Vec<u8>]) -> Vec<CertificateList> {
    ders.iter()
        .filter_map(|d| CertificateList::from_der(d).ok())
        .collect()
}

/// Parse OCSP response DER blobs into their inner `BasicOCSPResponse`.
fn parse_ocsps(ders: &[Vec<u8>]) -> Vec<BasicOcspResponse> {
    ders.iter()
        .filter_map(|d| {
            let rb = OcspResponse::from_der(d).ok()?.response_bytes?;
            BasicOcspResponse::from_der(rb.response.as_bytes()).ok()
        })
        .collect()
}

/// Outcome of verifying a single signature.
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    /// Whether the CMS signature is cryptographically valid over the byte range.
    pub valid: bool,
    /// The four `/ByteRange` integers `[start1, len1, start2, len2]`.
    pub byte_range: [i64; 4],
    /// Number of bytes covered by the signature.
    pub signed_len: usize,
    /// Whether the byte range covers the whole file except the signature hole.
    pub covers_whole_document: bool,
    /// Signer certificate subject DN, when the signature could be parsed.
    pub signer: Option<String>,
    /// Whether the signer certificate chains to a trusted root. `None` when no
    /// trust store was supplied or the entry is a document timestamp.
    pub chain_trusted: Option<bool>,
    /// Human-readable detail (error message when invalid).
    pub detail: String,
}

/// Report over all signatures found (PoC: parses the first one).
#[derive(Debug, Clone)]
pub struct SignatureReport {
    pub signatures: Vec<VerifiedSignature>,
}

impl SignatureReport {
    /// True if at least one signature was found and all found are valid.
    pub fn all_valid(&self) -> bool {
        !self.signatures.is_empty() && self.signatures.iter().all(|s| s.valid)
    }
}

/// Verify the signatures of a PDF file.
pub fn verify_pdf_file(path: impl AsRef<Path>) -> Result<SignatureReport> {
    let pdf = std::fs::read(path)?;
    verify_pdf_bytes(&pdf)
}

/// Verify all signatures of an in-memory PDF (one per `/ByteRange`).
pub fn verify_pdf_bytes(pdf: &[u8]) -> Result<SignatureReport> {
    verify_pdf_bytes_with_roots(pdf, &TrustStore::new())
}

/// Verify a PDF file, additionally validating each signer certificate chain
/// against `roots` (e.g. the ICP-Brasil roots).
pub fn verify_pdf_file_with_roots(
    path: impl AsRef<Path>,
    roots: &TrustStore,
) -> Result<SignatureReport> {
    let pdf = std::fs::read(path)?;
    verify_pdf_bytes_with_roots(&pdf, roots)
}

/// Verify an in-memory PDF, validating signer chains against `roots`.
pub fn verify_pdf_bytes_with_roots(pdf: &[u8], roots: &TrustStore) -> Result<SignatureReport> {
    let mut signatures = Vec::new();
    let mut from = 0;
    while let Some(rel) = find_sub(&pdf[from..], b"/ByteRange") {
        let br = from + rel;
        from = br + b"/ByteRange".len();
        signatures.push(verify_one(pdf, br, roots)?);
    }
    Ok(SignatureReport { signatures })
}

/// Verify the single signature whose `/ByteRange` begins at `br`.
fn verify_one(pdf: &[u8], br: usize, roots: &TrustStore) -> Result<VerifiedSignature> {
    let byte_range = parse_byte_range(&pdf[br..])?;
    let der = extract_cms(pdf, br)?;

    // Reassemble the signed content from the two byte-range segments.
    let [s1, l1, s2, l2] = byte_range.map(|v| v as usize);
    if s1 + l1 > pdf.len() || s2 + l2 > pdf.len() {
        return Err(Error::Malformed("ByteRange out of bounds".into()));
    }
    let mut signed = Vec::with_capacity(l1 + l2);
    signed.extend_from_slice(&pdf[s1..s1 + l1]);
    signed.extend_from_slice(&pdf[s2..s2 + l2]);

    let covers_whole_document = s1 == 0 && (s2 + l2) == pdf.len();

    // A `/DocTimeStamp` (SubFilter ETSI.RFC3161) holds a bare RFC 3161 token,
    // not a detached document signature — verify it differently.
    let is_timestamp = subfilter_before(pdf, br).as_deref() == Some(b"ETSI.RFC3161");

    let mut chain_trusted = None;
    let (valid, signer, mut detail) = if is_timestamp {
        match verify_doc_timestamp(&der, &signed) {
            Ok(()) => (
                true,
                None,
                "valid document timestamp (RFC 3161)".to_string(),
            ),
            Err(e) => (false, None, format!("{e}")),
        }
    } else {
        match cms_verify(&der, &signed) {
            Ok(v) => (
                true,
                Some(v.signer_subject.clone()),
                format!("valid CMS signature; signer: {}", v.signer_subject),
            ),
            Err(e) => (false, None, format!("{e}")),
        }
    };

    // Chain validation against the trust store (regular signatures only).
    if !is_timestamp && !roots.is_empty() {
        if let Ok((leaf, pool)) = signer_certificate_and_pool(&der) {
            let crls = parse_crls(&crate::dss::extract_dss_crls(pdf));
            let ocsps = parse_ocsps(&crate::dss::extract_dss_ocsps(pdf));
            let result = verify_chain(&leaf, &pool, roots, &crls, &ocsps, SystemTime::now());
            chain_trusted = Some(result.trusted);
            detail = format!("{detail}; chain: {}", result.detail);
        } else {
            chain_trusted = Some(false);
        }
    }

    Ok(VerifiedSignature {
        valid,
        byte_range,
        signed_len: l1 + l2,
        covers_whole_document,
        signer,
        chain_trusted,
        detail,
    })
}

/// Read the `/SubFilter` name that precedes the `/ByteRange` at `br` (each
/// signature dictionary writes SubFilter before ByteRange).
fn subfilter_before(pdf: &[u8], br: usize) -> Option<Vec<u8>> {
    let hay = &pdf[..br];
    let key = b"/SubFilter";
    let pos = (0..=hay.len().saturating_sub(key.len()))
        .rev()
        .find(|&i| &hay[i..i + key.len()] == key)?;
    let mut j = pos + key.len();
    while matches!(pdf.get(j), Some(b' ' | b'\r' | b'\n' | b'\t')) {
        j += 1;
    }
    if pdf.get(j) != Some(&b'/') {
        return None;
    }
    j += 1;
    let start = j;
    while !matches!(
        pdf.get(j),
        None | Some(b' ' | b'\r' | b'\n' | b'\t' | b'/' | b'>' | b'[' | b'(')
    ) {
        j += 1;
    }
    Some(pdf[start..j].to_vec())
}

/// Parse `[a b c d]` starting at a slice beginning with `/ByteRange`.
fn parse_byte_range(s: &[u8]) -> Result<[i64; 4]> {
    let open = find_sub(s, b"[").ok_or_else(|| Error::Malformed("ByteRange '[' missing".into()))?;
    let close =
        find_sub(&s[open..], b"]").ok_or_else(|| Error::Malformed("ByteRange ']' missing".into()))?
            + open;
    let inner = std::str::from_utf8(&s[open + 1..close])
        .map_err(|_| Error::Malformed("ByteRange not ASCII".into()))?;
    let nums: Vec<i64> = inner
        .split_whitespace()
        .filter_map(|t| t.parse::<i64>().ok())
        .collect();
    if nums.len() != 4 {
        return Err(Error::Malformed(format!(
            "expected 4 ByteRange ints, got {}",
            nums.len()
        )));
    }
    Ok([nums[0], nums[1], nums[2], nums[3]])
}

/// Pull the CMS DER out of the `/Contents <...>` hex string after `/ByteRange`.
fn extract_cms(pdf: &[u8], byte_range_pos: usize) -> Result<Vec<u8>> {
    let rel = find_sub(&pdf[byte_range_pos..], b"/Contents")
        .ok_or_else(|| Error::Malformed("/Contents not found".into()))?;
    let from = byte_range_pos + rel;
    let lt = from
        + find_sub(&pdf[from..], b"<").ok_or_else(|| Error::Malformed("Contents '<' missing".into()))?;
    let gt = lt
        + find_sub(&pdf[lt..], b">").ok_or_else(|| Error::Malformed("Contents '>' missing".into()))?;
    let raw = hex_decode(&pdf[lt + 1..gt])
        .ok_or_else(|| Error::Malformed("Contents not valid hex".into()))?;
    // Slice off the zero padding using the ASN.1 length header.
    if raw.first() != Some(&0x30) {
        return Err(Error::Malformed("CMS does not start with SEQUENCE".into()));
    }
    let len = der_total_len(&raw)
        .ok_or_else(|| Error::Malformed("cannot read CMS DER length".into()))?;
    if len > raw.len() {
        return Err(Error::Malformed("CMS DER length exceeds placeholder".into()));
    }
    Ok(raw[..len].to_vec())
}
