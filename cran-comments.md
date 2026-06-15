## Submission notes

This is the first CRAN submission of `signer`.

`signer` digitally signs and verifies PDF documents. All cryptography and PDF
manipulation are performed by a bundled, pure-Rust backend (the `pdf_signer`
crate); there is no Java runtime, OpenSSL, or external command-line dependency.

### Rust / SystemRequirements

The package needs the Rust toolchain (`cargo`, `rustc`) at build time, declared
in `SystemRequirements`. To allow a fully offline, network-free build (as
required on CRAN's build machines), the source of all Rust dependencies is
vendored into `src/rust/vendor.tar.xz` and unpacked by `src/Makevars` at build
time. This is the same mechanism used by other CRAN packages with a Rust
backend (e.g. `gifski`, `rextendr`-based packages).

Because of the vendored sources, the source tarball is larger than usual
(`src/rust/vendor.tar.xz` is ~18 MB). The unpacked sources are removed after the
build. We believe this is unavoidable for an offline Rust build and is in line
with precedent; please let us know if a different arrangement is preferred.

### Bundled third-party code

The vendored crates remain under the copyright of their respective authors and
are distributed under permissive licences (MIT, Apache-2.0, BSD, ISC, Zlib,
Unicode-3.0, 0BSD, Unlicense or CDLA-Permissive-2.0). They are credited as
copyright holders in `Authors@R` and enumerated in `inst/AUTHORS`.

## Package name

There is a Bioconductor package named `signeR`, which differs from `signer`
only in letter case. The names are distinct words (`signer` = "one who signs";
`signeR` = "signature exposure in R") with unrelated scopes (PDF signing vs.
mutational-signature analysis). We are happy to rename the package if CRAN
considers the case-insensitive clash unacceptable.

## Test environments

* local macOS, R release
* (please add the win-builder / R-hub results obtained for the actual submission)

## R CMD check results

On CRAN's build machines we expect 0 errors | 0 warnings | NOTEs for:

* New submission.
* Installed size (~12 MB) and source tarball size (~18 MB), both driven by the
  vendored Rust sources and the compiled static library, as explained above.

Locally we additionally see two environment-specific messages that will not
appear on CRAN's infrastructure: a linker warning about an SDK version mismatch
(our toolchain's macOS SDK is newer than the one R was built against) and a
"HTML Tidy not recent enough" NOTE (our local `tidy` is outdated).
