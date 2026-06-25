## Submission notes

This is a resubmission of `pdfsigner` (0.2.4) addressing the issue reported by
Prof. Brian Ripley on the M1mac additional check for 0.2.2.

`pdfsigner` digitally signs and verifies PDF documents. All cryptography and PDF
manipulation are performed by a bundled, pure-Rust backend (the `pdf_signer`
crate); there is no Java runtime, OpenSSL, or external command-line dependency.

### Fix for the M1mac linker WARNING (0.2.2)

The M1mac check of 0.2.2 reported "object file ... was built for newer 'macOS'
version (26.5) than being linked (26.0)" for the C/assembly object files of the
bundled `ring` crate. The cause is that, when `MACOSX_DEPLOYMENT_TARGET` is
unset, the macOS deployment target chosen by the `cc` crate (the host SDK
version) differs from the one used by `rustc` and by R's link step. We now
export an explicit `MACOSX_DEPLOYMENT_TARGET` for the `cargo build` step on
macOS (in `tools/config.R` / `src/Makevars.in`), using R's own value when set
and otherwise the per-architecture rustc default minimum, so all objects share
a single deployment target <= R's link target and the warning no longer occurs.

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

## Test environments

* local macOS (R 4.6.0), R CMD check --as-cran
* win-builder, R-devel (R Under development, 2026-06-24 r90190 ucrt): OK, 1 NOTE
  (see below)

## R CMD check results

We expect 0 errors | 0 warnings, including on the M1mac additional check that
previously warned (the deployment-target fix above eliminates that WARNING).

The following NOTEs are expected:

* "Days since last update: N". This release is a quick resubmission requested
  by the CRAN team (Prof. Ripley) to address the M1mac WARNING in 0.2.2; the
  only changes are the macOS deployment-target build fix described above.
* Installed size (~12 MB) and source tarball size (~18 MB), both driven by the
  vendored Rust sources and the compiled static library, as explained above.

Locally we additionally see a "HTML Tidy not recent enough" NOTE that is
environment-specific (our local `tidy` is outdated) and will not appear on
CRAN's infrastructure.
