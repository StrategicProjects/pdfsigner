## Submission notes

This is a resubmission of `pdfsigner` (0.2.5) addressing the installation
ERROR reported by Prof. Brian Ripley on 2026-06-26 via the "Additional issues"
/ donttest check (rustc version too old for vendored dependencies).

`pdfsigner` digitally signs and verifies PDF documents. All cryptography and PDF
manipulation are performed by a pure-Rust backend (the `pdf_signer` crate,
published on crates.io and vendored for the offline CRAN build); there is no
Java runtime, OpenSSL, or external command-line dependency.

### Fix for the rustc/MSRV installation ERROR (0.2.4)

Prof. Ripley's check machine (rustc 1.86.0) failed to install 0.2.4 with:

```
error: rustc 1.86.0 is not supported by the following packages:
   time@0.3.49 requires rustc 1.88.0
   time-core@0.1.9 requires rustc 1.88.0
   time-macros@0.2.29 requires rustc 1.88.0
```

`time`/`time-core`/`time-macros` are transitive dependencies (via `lopdf` and
`x509-parser`/`asn1-rs`) that are not pinned in our own `Cargo.toml` files, so
`cargo vendor` picked up their latest 0.3.x patch releases, which had quietly
raised the crates' MSRV from rustc 1.83.0 to 1.88.0 (12 months old at
submission time, i.e. newer than the toolchain-currency CRAN expects). We now
pin `time = "=0.3.45"` (with the matching `time-core 0.1.7` /
`time-macros 0.2.25`, MSRV 1.83.0) in `src/rust/Cargo.lock` before vendoring,
so the vendored build only requires a rustc that is well over two years old.

### Fix for the M1mac linker WARNING (0.2.2, still in effect)

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

* local macOS (R 4.6.0, rustc 1.95.0), R CMD check --as-cran, plus an offline
  build from the regenerated `src/rust/vendor.tar.xz` (the exact mechanism
  CRAN's build machines use)
* win-builder, R-devel: to be re-run for this submission

## R CMD check results

We expect 0 errors | 0 warnings. In particular, `cargo build --offline` against
the regenerated vendor tarball now succeeds with rustc 1.83.0+ (verified
locally by checking each pinned crate's declared `rust-version`), which covers
Prof. Ripley's check machine (rustc 1.86.0).

The following NOTEs are expected:

* "Days since last update: N". This release is a quick resubmission requested
  by the CRAN team (Prof. Ripley) to address the rustc/MSRV installation ERROR
  described above; the only functional changes are the `time` crate downgrade
  and vendoring `pdf_signer` from crates.io instead of a bundled path copy
  (same version, no behavior change).
* Installed size (~12 MB) and source tarball size (~18 MB), both driven by the
  vendored Rust sources and the compiled static library, as explained above.

Locally we additionally see a "HTML Tidy not recent enough" NOTE that is
environment-specific (our local `tidy` is outdated) and will not appear on
CRAN's infrastructure.
