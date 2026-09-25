# Verify the digital signatures of a PDF

Cryptographically verifies every signature and document timestamp in
`pdf_file` using the bundled Rust backend. Each signature is checked by
re-deriving its signed byte range, validating the CMS profile
(`content-type`, `message-digest`, ESS certificate binding) and the
signer's signature over the signed attributes. The document is also
judged **as a whole**: it is only intact when the last valid signature
or document timestamp covers the entire file, or when everything
appended after it is a PAdES `/DSS` (long-term validation material).
Content changed after signing therefore fails `document_intact` even
though the original signature still verifies over its own bytes.

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
  (and each timestamp authority's) is validated against these roots and
  reported in `chain_trusted`; for timestamped signatures the chain is
  judged at the timestamp's `genTime`, exposed as `trusted_time`.

## Value

A list with one entry per signature or document timestamp, in file
order. Each entry is a named list with `valid` (logical), `is_timestamp`
(logical, `TRUE` for a `/DocTimeStamp`), `signer` (subject DN),
`chain_trusted` (logical or `NA` when no `roots` given),
`covers_whole_document` (logical), `trusted_time` (seconds since the
Unix epoch of the trusted timestamp used, or `NA`), `signed_len`
(bytes), `byte_range` (numeric length-4) and `detail`. The list carries
three logical attributes with the document-level verdict:
`document_intact`, `all_valid` (every entry valid and the document
intact) and `all_trusted` (`all_valid` and every entry chains to one of
`roots`; always `FALSE` without `roots`). A length-zero list means no
signatures were found.

## Examples

``` r
if (FALSE) { # \dontrun{
result <- verify_pdf_signature("signed.pdf", roots = "icp-brasil-roots.pem")
vapply(result, function(s) s$valid, logical(1))
attr(result, "all_trusted")   # the one-line verdict
} # }
```
