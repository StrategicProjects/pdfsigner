## Submission notes

This is a new submission of `pdfsigner` (0.3.0). The package was on CRAN until
2026-07-15, when 0.2.5 was archived after the "Additional issues" / donttest
check on Prof. Ripley's machine (rustc 1.86.0) failed to install it. We have
identified and fixed the root cause and, more importantly, changed how the
Rust dependency set is chosen so that the build now targets a toolchain about
two years old, as CRAN's policy for Rust packages requires.

`pdfsigner` digitally signs and verifies PDF documents. All cryptography and PDF
manipulation are performed by a pure-Rust backend (the `pdf_signer` crate,
published on crates.io and vendored for the offline CRAN build); there is no
Java runtime, OpenSSL, or external command-line dependency.

### Why 0.2.5 failed to install on rustc 1.86.0, and the fix

0.2.5 pinned the `time` crate to a version with MSRV 1.83, which addressed the
error reported for 0.2.4 (`time@0.3.49 requires rustc 1.88.0`). It still
failed on rustc 1.86.0 because of a *second* transitive dependency,
`p12-keystore` 0.2.1, which uses Rust 2024-edition syntax (let-chains,
stabilised in rustc 1.88.0) **without declaring a `rust-version`**, so cargo
could not report the incompatibility up front; the crate simply failed to
compile. We apologise for not catching this before the resubmission.

For 0.3.0 the approach is systematic rather than crate-by-crate:

* The backend crate `pdf_signer` (0.3.2) now declares `rust-version = "1.81"`
  and depends on `p12-keystore` 0.1.5 (same API, 2021 edition) instead of
  0.2.x, which is 2024 edition (rustc 1.85+).
* The vendored dependency set in `src/rust/Cargo.lock` / `vendor.tar.xz` is
  resolved with cargo's MSRV-aware resolver
  (`CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`, honouring
  `rust-version = 1.81` in `src/rust/Cargo.toml`), which selects the newest
  release of every dependency that supports rustc 1.81 (e.g. `time` 0.3.44,
  `ureq` 3.2.1, `base64ct` 1.7.3, `indexmap` 2.11.4). Crates that do not
  declare a `rust-version` were audited by hand: `getrandom` is pinned to
  0.3.1 because its later WebAssembly-only dependencies are 2024 edition,
  and cargo 1.81 refuses to parse any vendored 2024-edition manifest even
  for targets it never builds. The vendored set contains **no** 2024-edition
  crate and no crate with `rust-version` above 1.81.0 (September 2024).
* We verified this by installing the exact source tarball offline (the
  mechanism CRAN's machines use, from `vendor.tar.xz`) with **rustc 1.81.0**
  and **rustc 1.86.0** (Prof. Ripley's version), both successfully, in
  addition to the current stable toolchain.

### What changed for users (0.3.0)

The engine release closes a security review of the verification path: the
package now judges a PDF as a whole (`document_intact`, `all_valid`,
`all_trusted` attributes on the result of `verify_pdf_signature()`), validates
timestamp authorities as such, honours revocation dated at or before the
signing time, writes non-ASCII signature metadata as UTF-16, preserves the
document's `/Info`, merges long-term validation material, and refuses to sign
encrypted or DocMDP-certified PDFs instead of producing a corrupted file. See
`NEWS.md`.

### Rust / SystemRequirements

The package needs the Rust toolchain (`cargo`, `rustc` >= 1.81) at build time,
declared in `SystemRequirements`. To allow a fully offline, network-free build,
the source of all Rust dependencies is vendored into `src/rust/vendor.tar.xz`
and unpacked by `src/Makevars` at build time (the mechanism used by other CRAN
packages with a Rust backend). The source tarball is therefore larger than
usual (~18 MB); the unpacked sources are removed after the build.

The M1mac deployment-target fix from 0.2.4 (`MACOSX_DEPLOYMENT_TARGET` exported
for the `cargo build` step) is still in effect.

### Bundled third-party code

The vendored crates remain under the copyright of their respective authors and
are distributed under permissive licences (MIT, Apache-2.0, BSD, ISC, Zlib,
Unicode-3.0, 0BSD, Unlicense or CDLA-Permissive-2.0). They are credited as
copyright holders in `Authors@R` and enumerated in `inst/AUTHORS`.

## Test environments

* local macOS (R 4.6.0), `R CMD check --as-cran`
* offline installation of the built tarball with rustc 1.81.0, rustc 1.86.0
  and rustc 1.97.0 (stable)

## R CMD check results

0 errors | 0 warnings | 1 NOTE.

The NOTE is "CRAN incoming feasibility: New submission / Package was archived
on CRAN", which this note addresses. Locally we additionally see the
"installed size" INFO (~12 MB, the compiled static library) driven by the
vendored Rust sources as explained above.
