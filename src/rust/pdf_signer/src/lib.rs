//! # pdf_signer
//!
//! Minimal, self-contained library to **digitally sign** PDF documents with a
//! PKCS#12 (`.p12`/`.pfx`) keystore and to **verify** existing signatures.
//!
//! This is a proof of concept intended to replace the bundled
//! `BatchPDFSignPortable.jar` (Java/PDFBox) used by the R package `signer`,
//! removing the Java runtime dependency and the 13 MB binary blob.
//!
//! ## What it does
//! * [`sign_pdf_file`] / [`sign_pdf_bytes`]: append a signature field and an
//!   `adbe.pkcs7.detached` CMS signature over the whole document.
//! * [`verify_pdf_file`] / [`verify_pdf_bytes`]: re-extract the signed byte
//!   range, validate the CMS signature cryptographically and report signer info.
//!
//! ## Scope of the PoC
//! * Single, invisible signature (no visual appearance stream yet).
//! * Full-rewrite save (not an incremental update) — fine for a first
//!   signature, revisit before multi-signature support.
//! * CMS is produced via the system OpenSSL (`openssl` crate). A pure-Rust
//!   RustCrypto backend is the path for a CRAN-friendly, vendored build.

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
