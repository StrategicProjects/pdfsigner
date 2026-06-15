//! RFC 3161 timestamp client (for PAdES-B-T).
//!
//! Builds a `TimeStampReq` over a message imprint, POSTs it to a Time-Stamping
//! Authority over plain HTTP, and returns the `TimeStampToken` (a CMS
//! `ContentInfo`) to embed as an unsigned attribute.
//!
//! The HTTP client is a tiny hand-rolled `std::net` POST so the crate stays
//! pure-Rust and dependency-free. Only `http://` endpoints are supported;
//! `https://` would require a TLS stack (and a non-pure-Rust crypto provider).

#[cfg(not(feature = "https"))]
use std::io::{Read, Write};
#[cfg(not(feature = "https"))]
use std::net::TcpStream;
#[cfg(not(feature = "https"))]
use std::time::Duration;

use cms::content_info::ContentInfo;
use const_oid::db::rfc5912::ID_SHA_256;
use der::asn1::{BitString, OctetString};
use der::{Any, Decode, Encode, Sequence};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;

use crate::error::Error;
use crate::Result;

fn tsa<E: std::fmt::Display>(e: E) -> Error {
    Error::Crypto(e.to_string())
}

#[derive(Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

#[derive(Sequence)]
struct TimeStampReq {
    version: i32,
    message_imprint: MessageImprint,
    cert_req: bool,
}

#[derive(Sequence)]
struct PkiStatusInfo {
    status: i32,
    #[asn1(optional = "true")]
    _status_string: Option<Any>,
    #[asn1(optional = "true")]
    _fail_info: Option<BitString>,
}

#[derive(Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    token: Option<ContentInfo>,
}

/// Request an RFC 3161 timestamp token over `signature` from `tsa_url`
/// (an `http://...` endpoint). Returns the TimeStampToken `ContentInfo`.
pub(crate) fn request_timestamp(tsa_url: &str, signature: &[u8]) -> Result<ContentInfo> {
    let imprint = Sha256::digest(signature);
    let req = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: ID_SHA_256,
                parameters: None,
            },
            hashed_message: OctetString::new(imprint.to_vec()).map_err(tsa)?,
        },
        cert_req: true,
    };

    let body = req.to_der().map_err(tsa)?;
    let resp = http_post(tsa_url, "application/timestamp-query", &body)?;

    let parsed = TimeStampResp::from_der(&resp)
        .map_err(|e| Error::Crypto(format!("malformed TSA response: {e}")))?;
    // PKIStatus: 0 = granted, 1 = grantedWithMods.
    if !matches!(parsed.status.status, 0 | 1) {
        return Err(Error::Crypto(format!(
            "TSA rejected the request (PKIStatus {})",
            parsed.status.status
        )));
    }
    parsed
        .token
        .ok_or_else(|| Error::Crypto("TSA response carried no timestamp token".into()))
}

/// POST `body` to `url`. Returns the response body.
pub(crate) fn http_post(url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>> {
    fetch("POST", url, Some(content_type), body)
}

/// GET `url` (used to fetch CRLs for the DSS). Returns the response body.
pub(crate) fn http_get(url: &str) -> Result<Vec<u8>> {
    fetch("GET", url, None, &[])
}

/// Dispatch to the TLS-capable client when the `https` feature is on, otherwise
/// the dependency-free plain-HTTP client.
#[cfg(feature = "https")]
fn fetch(method: &str, url: &str, content_type: Option<&str>, body: &[u8]) -> Result<Vec<u8>> {
    let mut resp = if method == "POST" {
        let mut req = ureq::post(url);
        if let Some(ct) = content_type {
            req = req.header("Content-Type", ct);
        }
        req.send(body).map_err(tsa)?
    } else {
        ureq::get(url).call().map_err(tsa)?
    };
    resp.body_mut()
        .with_config()
        .limit(20 * 1024 * 1024)
        .read_to_vec()
        .map_err(tsa)
}

#[cfg(not(feature = "https"))]
fn fetch(method: &str, url: &str, content_type: Option<&str>, body: &[u8]) -> Result<Vec<u8>> {
    http_request_plain(method, url, content_type, body)
}

/// Minimal HTTP/1.1 request over plain TCP (no TLS). Returns the response body.
#[cfg(not(feature = "https"))]
fn http_request_plain(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Vec<u8>> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| Error::Crypto("URL must start with http:// (https is not supported)".into()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(tsa)?),
        None => (authority, 80),
    };

    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(20))).ok();

    let mut header = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: pdf_signer\r\n");
    if let Some(ct) = content_type {
        header.push_str(&format!("Content-Type: {ct}\r\nContent-Length: {}\r\n", body.len()));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush().ok();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    let idx = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Crypto("malformed HTTP response".into()))?;
    let head = &raw[..idx];
    let body_bytes = raw[idx + 4..].to_vec();

    let status_line = String::from_utf8_lossy(head.split(|&b| b == b'\n').next().unwrap_or(&[]));
    if !status_line.contains(" 200") {
        return Err(Error::Crypto(format!("HTTP error: {}", status_line.trim())));
    }

    if String::from_utf8_lossy(head)
        .to_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return dechunk(&body_bytes);
    }
    Ok(body_bytes)
}

/// Decode HTTP/1.1 chunked transfer-encoding.
#[cfg(not(feature = "https"))]
fn dechunk(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let line_end = i + data[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| Error::Crypto("bad chunk header".into()))?;
        let size_field = String::from_utf8_lossy(&data[i..line_end]);
        let size = usize::from_str_radix(size_field.split(';').next().unwrap_or("").trim(), 16)
            .map_err(tsa)?;
        i = line_end + 2;
        if size == 0 {
            break;
        }
        if i + size > data.len() {
            return Err(Error::Crypto("truncated chunk".into()));
        }
        out.extend_from_slice(&data[i..i + size]);
        i += size + 2;
    }
    Ok(out)
}
