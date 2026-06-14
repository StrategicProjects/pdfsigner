use extendr_api::prelude::*;
use pdf_signer::{sign_pdf_file, verify_pdf_file, Appearance, SignOptions};

/// Empty string -> None, otherwise Some.
fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Sign `pdf_file` with a PKCS#12 keystore, writing `output_file`.
///
/// When `visible` is TRUE, a bordered signature box with `appearance_text`
/// is drawn on `page` at `[x, y, width, height]`. Errors become R errors.
/// @export
#[extendr]
#[allow(clippy::too_many_arguments)]
fn rust_sign_pdf(
    pdf_file: &str,
    output_file: &str,
    keystore_path: &str,
    keystore_password: &str,
    reason: &str,
    name: &str,
    location: &str,
    contact_info: &str,
    signing_time: &str,
    visible: bool,
    page: i32,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    font_size: f64,
    appearance_text: &str,
    border: bool,
) -> std::result::Result<(), Error> {
    let appearance = visible.then(|| Appearance {
        page: page.max(1) as usize,
        x,
        y,
        width,
        height,
        font_size,
        text: appearance_text.to_string(),
        border,
    });

    let opts = SignOptions {
        reason: opt(reason),
        name: opt(name),
        location: opt(location),
        contact_info: opt(contact_info),
        signing_time: opt(signing_time),
        appearance,
        ..Default::default()
    };

    sign_pdf_file(
        pdf_file,
        output_file,
        keystore_path,
        keystore_password,
        &opts,
    )
    .map_err(|e| Error::Other(e.to_string()))
}

/// Verify all signatures in `pdf_file`. Returns a list with one named list per
/// signature (`valid`, `signer`, `covers_whole_document`, `signed_len`,
/// `byte_range`, `detail`). An empty list means no signatures were found.
/// @export
#[extendr]
fn rust_verify_pdf(pdf_file: &str) -> std::result::Result<Robj, Error> {
    let report = verify_pdf_file(pdf_file).map_err(|e| Error::Other(e.to_string()))?;

    let items: Vec<Robj> = report
        .signatures
        .iter()
        .map(|s| {
            let byte_range: Vec<f64> = s.byte_range.iter().map(|v| *v as f64).collect();
            list!(
                valid = s.valid,
                signer = s.signer.clone().unwrap_or_default(),
                covers_whole_document = s.covers_whole_document,
                signed_len = s.signed_len as f64,
                byte_range = byte_range,
                detail = s.detail.clone()
            )
            .into_robj()
        })
        .collect();

    Ok(List::from_values(items).into_robj())
}

extendr_module! {
    mod signer;
    fn rust_sign_pdf;
    fn rust_verify_pdf;
}
