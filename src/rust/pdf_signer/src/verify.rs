//! Verification path: re-derive the signed byte range and validate the CMS.

use std::path::Path;

use std::time::SystemTime;

use der::Decode;
use lopdf::{Dictionary, Document};
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, OcspResponse};

use crate::crypto::{
    cms_verify, signer_certificate_and_pool, verify_doc_timestamp, verify_embedded_timestamp,
};
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
    /// True if at least one signature was found and all found are
    /// cryptographically valid. This says **nothing** about trust — a
    /// self-signed or untrusted signature can still be `all_valid`. When a
    /// trust store was supplied, use [`all_trusted`](Self::all_trusted).
    pub fn all_valid(&self) -> bool {
        !self.signatures.is_empty() && self.signatures.iter().all(|s| s.valid)
    }

    /// True if every signature is valid ([`all_valid`](Self::all_valid)) **and**
    /// none chains to an untrusted root. Use this when a trust store was
    /// supplied; entries with no trust result (`chain_trusted == None`, e.g.
    /// document timestamps) are not treated as failures.
    pub fn all_trusted(&self) -> bool {
        self.all_valid()
            && self
                .signatures
                .iter()
                .all(|s| s.chain_trusted != Some(false))
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

/// A signature located in the document: its `/ByteRange`, the raw `/Contents`
/// bytes (hex-decoded, including any zero padding), and whether it is a document
/// timestamp (`/SubFilter /ETSI.RFC3161`).
struct SigLoc {
    byte_range: [i64; 4],
    contents: Vec<u8>,
    is_timestamp: bool,
}

/// Verify an in-memory PDF, validating signer chains against `roots`.
pub fn verify_pdf_bytes_with_roots(pdf: &[u8], roots: &TrustStore) -> Result<SignatureReport> {
    let mut signatures = Vec::new();
    for sig in collect_signatures(pdf) {
        signatures.push(verify_one(pdf, &sig, roots)?);
    }
    Ok(SignatureReport { signatures })
}

/// Locate every signature by document **structure** — the signature dictionaries
/// (`/ByteRange` + `/Contents`) reachable in the parsed object set — rather than
/// by scanning the raw bytes for `/ByteRange`, which could match a string,
/// stream or comment. Reads `/ByteRange` and `/SubFilter` from the dictionary,
/// so it does not depend on key order. Falls back to a byte scan only if the
/// document cannot be parsed at all.
fn collect_signatures(pdf: &[u8]) -> Vec<SigLoc> {
    // Only fall back to scanning when the document cannot be parsed at all. A
    // document that parses but has no signature dictionaries genuinely has no
    // signatures — a `/ByteRange` found loose in a stream or string is not one.
    let Ok(doc) = Document::load_mem(pdf) else {
        return collect_signatures_by_scan(pdf);
    };
    let mut sigs: Vec<SigLoc> = doc
        .objects
        .values()
        .filter_map(|obj| obj.as_dict().ok())
        .filter_map(signature_from_dict)
        .collect();
    // Report in file order: an earlier signature's `/Contents` hex string (which
    // begins at `s1 + l1`) sits at a lower offset than a later one.
    sigs.sort_by_key(|s| s.byte_range[0] + s.byte_range[1]);
    sigs
}

/// Recognize a signature dictionary and read the fields we need, regardless of
/// key order. A signature dictionary carries both a `/ByteRange` array and a
/// `/Contents` string.
fn signature_from_dict(dict: &Dictionary) -> Option<SigLoc> {
    let contents = dict.get(b"Contents").ok()?.as_str().ok()?.to_vec();
    let arr = dict.get(b"ByteRange").ok()?.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let mut byte_range = [0i64; 4];
    for (slot, v) in byte_range.iter_mut().zip(arr) {
        *slot = v.as_i64().ok()?;
    }
    let is_timestamp = dict.get(b"SubFilter").ok().and_then(|o| o.as_name().ok())
        == Some(b"ETSI.RFC3161".as_ref());
    Some(SigLoc {
        byte_range,
        contents,
        is_timestamp,
    })
}

/// Fallback enumeration for documents that fail to parse: scan the raw bytes for
/// each `/ByteRange` (the historical behavior).
fn collect_signatures_by_scan(pdf: &[u8]) -> Vec<SigLoc> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = find_sub(&pdf[from..], b"/ByteRange") {
        let br = from + rel;
        from = br + b"/ByteRange".len();
        if let (Ok(byte_range), Some(contents)) =
            (parse_byte_range(&pdf[br..]), scan_contents(pdf, br))
        {
            let is_timestamp = subfilter_before(pdf, br).as_deref() == Some(b"ETSI.RFC3161");
            out.push(SigLoc {
                byte_range,
                contents,
                is_timestamp,
            });
        }
    }
    out
}

/// Scan for the `/Contents <...>` hex string following `/ByteRange` at `br` and
/// decode it (fallback path only).
fn scan_contents(pdf: &[u8], br: usize) -> Option<Vec<u8>> {
    let from = br + find_sub(&pdf[br..], b"/Contents")?;
    let lt = from + find_sub(&pdf[from..], b"<")?;
    let gt = lt + find_sub(&pdf[lt..], b">")?;
    hex_decode(&pdf[lt + 1..gt])
}

/// Verify a single located signature.
fn verify_one(pdf: &[u8], sig: &SigLoc, roots: &TrustStore) -> Result<VerifiedSignature> {
    let byte_range = sig.byte_range;
    if byte_range.iter().any(|&v| v < 0) {
        return Err(Error::Malformed("negative ByteRange value".into()));
    }
    let [s1, l1, s2, l2] = byte_range.map(|v| v as usize);
    if s1 + l1 > pdf.len() || s2 + l2 > pdf.len() {
        return Err(Error::Malformed("ByteRange out of bounds".into()));
    }

    // The CMS comes from the structurally-parsed `/Contents`, not from the bytes
    // the ByteRange happens to point at.
    let der = cms_from_contents(&sig.contents)?;

    // Reassemble the signed content from the two byte-range segments.
    let mut signed = Vec::with_capacity(l1 + l2);
    signed.extend_from_slice(&pdf[s1..s1 + l1]);
    signed.extend_from_slice(&pdf[s2..s2 + l2]);

    // "Covers the whole document" requires spanning byte 0 to EOF *and* that the
    // only excluded bytes — the ByteRange gap `[s1+l1, s2)` — are exactly the
    // `/Contents <...>` hex string. Otherwise a ByteRange could leave arbitrary
    // unsigned bytes in the gap and still claim full coverage.
    let covers_whole_document = s1 == 0
        && (s2 + l2) == pdf.len()
        && gap_is_contents(pdf, s1 + l1, s2, &sig.contents);

    let is_timestamp = sig.is_timestamp;
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
            // PAdES: judge the chain at signing time so a signature stays valid
            // after the certificate expires — but only when that time comes from
            // a trustworthy source. A `genTime` is used only if its RFC 3161
            // token verifies AND the TSA itself chains to a trusted root;
            // otherwise we fall back to "now". The signer-asserted `signingTime`
            // is never used (it would let an expired/revoked cert backdate
            // itself past expiry/revocation checks).
            let at = trusted_time(&der, roots, &crls, &ocsps).unwrap_or_else(SystemTime::now);
            let result = verify_chain(&leaf, &pool, roots, &crls, &ocsps, at);
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

/// The reference instant for validating the signer chain: the `genTime` of the
/// signature's embedded RFC 3161 timestamp, but only when that token verifies
/// cryptographically *and* the TSA's own certificate chains to a trusted root.
/// Returns `None` otherwise, so the caller validates at the current time.
fn trusted_time(
    der: &[u8],
    roots: &TrustStore,
    crls: &[CertificateList],
    ocsps: &[BasicOcspResponse],
) -> Option<SystemTime> {
    let ts = verify_embedded_timestamp(der).ok()?;
    // The TSA must itself be trusted (validated at the present time), else a
    // self-issued TSA could assert any genTime to dodge expiry/revocation.
    verify_chain(&ts.tsa_leaf, &ts.tsa_pool, roots, crls, ocsps, SystemTime::now())
        .trusted
        .then_some(ts.gen_time)
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

/// Slice the real CMS out of the raw `/Contents` bytes, dropping the zero
/// padding using the ASN.1 length header.
fn cms_from_contents(contents: &[u8]) -> Result<Vec<u8>> {
    if contents.first() != Some(&0x30) {
        return Err(Error::Malformed("CMS does not start with SEQUENCE".into()));
    }
    let len = der_total_len(contents)
        .ok_or_else(|| Error::Malformed("cannot read CMS DER length".into()))?;
    if len > contents.len() {
        return Err(Error::Malformed("CMS DER length exceeds placeholder".into()));
    }
    Ok(contents[..len].to_vec())
}

/// True if the ByteRange gap `[gap_start, gap_end)` is exactly the `/Contents`
/// hex string `<...>` whose decoded value is `contents` — i.e. the signature
/// excludes nothing but its own Contents.
fn gap_is_contents(pdf: &[u8], gap_start: usize, gap_end: usize, contents: &[u8]) -> bool {
    if gap_start >= gap_end || gap_end > pdf.len() {
        return false;
    }
    let gt = gap_end - 1;
    pdf.get(gap_start) == Some(&b'<')
        && pdf.get(gt) == Some(&b'>')
        && hex_decode(&pdf[gap_start + 1..gt]).as_deref() == Some(contents)
}
