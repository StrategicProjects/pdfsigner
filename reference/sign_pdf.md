# Digitally sign a PDF document

Signs `pdf_file` using an RSA key + certificate stored in a PKCS#12
(`.p12`/`.pfx`) keystore, writing the signed document to `output_file`.
The signature is a detached `adbe.pkcs7.detached` CMS over the whole
document and is added as an incremental update, so any pre-existing
signatures stay valid.

## Usage

``` r
sign_pdf(
  pdf_file,
  output_file,
  keystore_path = Sys.getenv("KEYSTORE_PATH"),
  keystore_password = Sys.getenv("KEY_PASSWORD"),
  signtext = NULL,
  validate_link = NULL,
  reason = NULL,
  signer_name = NULL,
  page = 1,
  x = 36,
  y = 36,
  width = 320,
  height = 64,
  font_size = 8,
  font = NULL,
  image = NULL,
  border = TRUE,
  translate = FALSE,
  tsa_url = NULL,
  pades_level = c("bb", "bt", "blt", "blta")
)
```

## Arguments

- pdf_file:

  Path to the input PDF.

- output_file:

  Path where the signed PDF is written.

- keystore_path:

  Path to the `.p12`/`.pfx` keystore. Defaults to the `KEYSTORE_PATH`
  environment variable.

- keystore_password:

  Password for the keystore. Defaults to the `KEY_PASSWORD` environment
  variable.

- signtext:

  Optional text for a *visible* signature box. When `NULL` or empty the
  signature is invisible.

- validate_link:

  Optional validation URL appended to the visible box.

- reason, signer_name:

  Optional `/Reason` and `/Name` for the signature dictionary.

- page:

  1-based page number for the visible box.

- x, y, width, height:

  Visible box geometry, in PDF points (origin at the page's
  bottom-left).

- font_size:

  Font size for the visible box, in points.

- font:

  Optional path to a TrueType/OpenType font file (`.ttf`/`.otf`) to
  embed in the visible box. When `NULL`, the standard Helvetica is used.
  Only the WinAnsi (Latin-1) glyph range is embedded. Ignored for
  invisible signatures.

- image:

  Optional path to a PNG or JPEG logo drawn in the visible box. Ignored
  for invisible signatures.

- border:

  Draw a border around the visible box.

- translate:

  If `TRUE`, the date label in the visible box is in Portuguese;
  otherwise English.

- tsa_url:

  Optional RFC 3161 Time-Stamping Authority `http://` URL. Required for
  `pades_level` `"bt"` and above. Requires network access.

- pades_level:

  PAdES conformance level: `"bb"` (baseline, default), `"bt"` (+
  signature timestamp), `"blt"` (+ DSS with certificates and CRLs), or
  `"blta"` (+ a document timestamp over the whole file). Levels `"bt"`
  and above need `tsa_url`.

## Value

Invisibly, the path to the signed PDF. Raises an error on failure.

## Examples

``` r
if (FALSE) { # \dontrun{
sign_pdf(
  pdf_file = "input.pdf",
  output_file = "signed.pdf",
  keystore_path = "keystore.p12",
  keystore_password = "password",
  signtext = "Document digitally signed by CastLab",
  validate_link = "https://castlab.org/validate",
  translate = TRUE
)
} # }
```
