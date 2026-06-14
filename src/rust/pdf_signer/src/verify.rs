//! Verification path: re-derive the signed byte range and validate the CMS.

use std::path::Path;

use crate::crypto::cms_verify;
use crate::error::Error;
use crate::util::{der_total_len, find_sub, hex_decode};
use crate::Result;

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
    let mut signatures = Vec::new();
    let mut from = 0;
    while let Some(rel) = find_sub(&pdf[from..], b"/ByteRange") {
        let br = from + rel;
        from = br + b"/ByteRange".len();
        signatures.push(verify_one(pdf, br)?);
    }
    Ok(SignatureReport { signatures })
}

/// Verify the single signature whose `/ByteRange` begins at `br`.
fn verify_one(pdf: &[u8], br: usize) -> Result<VerifiedSignature> {
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

    let (valid, signer, detail) = match cms_verify(&der, &signed) {
        Ok(v) => (
            true,
            Some(v.signer_subject.clone()),
            format!("valid CMS signature; signer: {}", v.signer_subject),
        ),
        Err(e) => (false, None, format!("{e}")),
    };

    Ok(VerifiedSignature {
        valid,
        byte_range,
        signed_len: l1 + l2,
        covers_whole_document,
        signer,
        detail,
    })
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
