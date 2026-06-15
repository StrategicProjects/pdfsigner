# Verify the digital signatures of a PDF

Cryptographically verifies every signature in `pdf_file` using the
bundled Rust backend. Each signature is checked by re-deriving its
signed byte range, confirming the `messageDigest` against `SHA-256` of
the content and validating the signer's RSA signature over the signed
attributes.

## Usage

``` r
verify_pdf_signature(pdf_file, roots = NULL)
```

## Arguments

- pdf_file:

  Path to the PDF to verify.

- roots:

  Optional path to a PEM file of trusted root certificates (e.g. the
  ICP-Brasil AC Raiz set). When supplied, each signer certificate chain
  is validated against these roots and reported in `chain_trusted`.

## Value

A list with one entry per signature. Each entry is a named list with
`valid` (logical), `signer` (subject DN), `chain_trusted` (logical or
`NA` when no `roots` given), `covers_whole_document` (logical),
`signed_len` (bytes), `byte_range` (numeric length-4) and `detail`. A
length-zero list means no signatures were found.

## Examples

``` r
if (FALSE) { # \dontrun{
result <- verify_pdf_signature("signed.pdf", roots = "icp-brasil-roots.pem")
vapply(result, function(s) s$valid, logical(1))
} # }
```
