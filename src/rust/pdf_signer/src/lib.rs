//! # pdf_signer
//!
//! Pure-Rust, self-contained library to **digitally sign** (PAdES) and
//! **verify** PDF documents with a PKCS#12 (`.p12`/`.pfx`) keystore. It replaces
//! the bundled `BatchPDFSignPortable.jar` (Java/PDFBox) used by the R package
//! `signer`, removing the Java runtime dependency and the binary blob.
//!
//! ## What it does
//! * [`sign_pdf_file`] / [`sign_pdf_bytes`]: append a signature field (optionally
//!   with a visible appearance) and an `ETSI.CAdES.detached` CMS signature as an
//!   **incremental update**, so any prior signature stays valid. Targets PAdES
//!   B-B through B-LTA (RFC 3161 signature & document timestamps, `/DSS`).
//! * [`verify_pdf_file`] / [`verify_pdf_bytes`]: re-extract the signed byte
//!   range, validate the CMS signature cryptographically, report signer info,
//!   and optionally validate the signer chain against a [`TrustStore`].
//!
//! ## Notes
//! * Keys: RSA (PKCS#1 v1.5), ECDSA (P-256/P-384), Ed25519.
//! * 100% pure Rust (RustCrypto) — no OpenSSL, no Java, no system C libraries.
//!   An optional `https` feature (ureq/rustls) enables TLS TSA/CRL/OCSP.
//! * Incremental updates support both classic xref tables and xref streams.

mod appearance;
mod crypto;
mod dss;
mod error;
mod incremental;
mod policy;
mod sign;
pub mod testkit;
mod trust;
mod tsa;
mod util;
mod verify;

pub use error::Error;
pub use sign::{sign_pdf_bytes, sign_pdf_file, Appearance, PadesLevel, SignOptions};
pub use trust::TrustStore;
pub use verify::{
    verify_certificate_chain, verify_pdf_bytes, verify_pdf_bytes_with_roots, verify_pdf_file,
    verify_pdf_file_with_roots, SignatureReport, VerifiedSignature,
};

/// Convenience result type for the crate.
pub type Result<T> = std::result::Result<T, Error>;
