use thiserror::Error;

/// Errors that can occur while signing or verifying a PDF.
#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PDF parsing/serialization error: {0}")]
    Pdf(#[from] lopdf::Error),

    #[error("cryptography error: {0}")]
    Crypto(String),

    /// The placeholder reserved for the signature is too small for the
    /// produced CMS blob. Increase `SignOptions::signature_capacity`.
    #[error("signature does not fit in reserved placeholder: need {needed} bytes, have {capacity}")]
    PlaceholderTooSmall { needed: usize, capacity: usize },

    #[error("malformed PDF: {0}")]
    Malformed(String),

    #[error("signature verification failed: {0}")]
    Verification(String),
}
