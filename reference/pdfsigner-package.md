# pdfsigner: native PDF signing and verification

Digitally sign PDF documents with a PKCS#12 keystore and verify their
signatures. The heavy lifting is done by a bundled, pure-Rust backend
(the `pdf_signer` crate) — no Java, OpenSSL, or external command-line
tools are required.

## See also

Useful links:

- <https://github.com/StrategicProjects/pdfsigner>

- Report bugs at <https://github.com/StrategicProjects/pdfsigner/issues>

## Author

**Maintainer**: Andre Leite <leite@castlab.org>

Authors:

- Andre Leite <leite@castlab.org>

- Hugo Vasconcelos <hugo.vasconcelos@ufpe.br>

- Diogo Bezerra <diogo.bezerra@ufpe.br>

Other contributors:

- Authors of the vendored Rust crates (see inst/AUTHORS for the bundled
  crates and their licences) \[contributor, copyright holder\]
