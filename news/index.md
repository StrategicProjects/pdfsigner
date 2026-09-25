# Changelog

## pdfsigner 0.3.0

- Synced the pure-Rust backend to `pdf_signer` engine v0.3.1, which
  closes a multi-agent security review. Verification now judges the
  **whole document**:
  [`verify_pdf_signature()`](https://strategicprojects.github.io/pdfsigner/reference/verify_pdf_signature.md)
  returns the attributes `document_intact`, `all_valid` and
  `all_trusted`; a PDF whose content was changed by an unsigned
  incremental update after signing is no longer reported as valid
  overall (each signature still reports `valid` over its own byte
  range). Document timestamps get their own `chain_trusted`; timestamp
  authorities must carry the RFC 3161 `id-kp-timeStamping` purpose
  before their time is trusted; revocation dated at or before the
  signing time is honoured even from later CRL/OCSP evidence;
  certificate extensions are processed per RFC 5280 §6.1.3.
- New per-signature fields `is_timestamp` and `trusted_time`.
- Signing: `reason`, `name`, `location` and `contact_info` with
  non-ASCII text (e.g. “Aprovação”) are now written as UTF-16 text
  strings and render correctly in every viewer; the previous trailer’s
  `/Info` (Title, Author) is preserved; a second B-LT/B-LTA signature
  merges into the existing `/DSS`; the claimed signing time is written
  to `/M` by default. Encrypted PDFs (even with an empty user password)
  and documents certified with DocMDP `P=1` are refused with a clear
  error instead of producing a corrupted file.

## pdfsigner 0.2.5

CRAN release: 2026-07-02

- Accepted by CRAN on 2026-07-02.
- Fixed an installation ERROR on rustc 1.86.0 (reported for 0.2.4 via
  CRAN’s “Additional issues” / donttest check). Transitive dependencies
  `time`/`time-core`/`time-macros` (pulled in via `lopdf` and
  `x509-parser`/`asn1-rs`) had quietly raised their MSRV to rustc
  1.88.0. We now pin `time = "=0.3.45"` (MSRV 1.83.0) in
  `src/rust/Cargo.lock` before vendoring, so the offline build only
  requires a rustc over two years old.
- `pdf_signer` is now consumed as a normal crates.io dependency
  (`default-features = false`, `features = ['https']`) instead of a
  bundled, hand-synced path copy; `src/rust/vendor.tar.xz` was
  re-vendored accordingly. No user-facing behavior change.

## pdfsigner 0.2.4

CRAN release: 2026-06-26

- Fixed the M1mac linker WARNING (“object file … was built for newer
  ‘macOS’ version than being linked”) on the C/assembly objects of the
  `ring` crate, by exporting an explicit `MACOSX_DEPLOYMENT_TARGET` for
  the `cargo build` step (`tools/config.R` / `src/Makevars.in`) so all
  objects share a deployment target at or below R’s link target.

## pdfsigner 0.2.3

- Synced the pure-Rust backend to `pdf_signer` engine v0.2.0.

## pdfsigner 0.2.2

CRAN release: 2026-06-21

- CRAN submission. Do not regenerate the extendr wrappers at install
  time (the wrappers are committed); the Windows/CRAN build only runs
  `cargo build --lib`.

## pdfsigner 0.2.0

- Replaced the previous Java/`pdfsig` backend with a bundled pure-Rust
  engine wrapped via extendr. No Java, OpenSSL, or external command-line
  tools required.
- Public API:
  [`sign_pdf()`](https://strategicprojects.github.io/pdfsigner/reference/sign_pdf.md)
  and
  [`verify_pdf_signature()`](https://strategicprojects.github.io/pdfsigner/reference/verify_pdf_signature.md).
