# pdfsigner (R package) — guidance for Claude

R package that digitally signs/verifies PDFs by wrapping the pure-Rust
`pdf_signer` crate via **extendr**. No Java, no OpenSSL, no external tools.
**Submitted to CRAN** (v0.2.2; see `CRAN-SUBMISSION`).

> Renamed from `signer` → `pdfsigner` to avoid a case-insensitive CRAN clash
> with Bioconductor's `signeR`. The repo and dir are `pdfsigner`.

## Structure
- `R/sign.R` — public API: `sign_pdf()` / `verify_pdf_signature()`.
- `R/extendr-wrappers.R`, `NAMESPACE` — **generated**; do not hand-edit.
- `src/rust/` — the extendr crate (`Cargo.toml` lib name `pdfsigner`,
  `extendr_module! { mod pdfsigner }`), `src/entrypoint.c`
  (`R_init_pdfsigner` / `..._extendr`), `Makevars.in` / `Makevars.win.in`
  (`libpdfsigner.a` / `-lpdfsigner`).
- `src/rust/pdf_signer/` — a **bundled copy** of the standalone crate (path dep).
  Keep in sync with github.com/StrategicProjects/pdf_signer (currently v0.1.7).
- `src/rust/vendor.tar.xz` — vendored Rust deps for an **offline CRAN build**.

## Build / test / docs
```r
rextendr::document()      # regenerate wrappers + Rd + NAMESPACE (recompiles Rust)
devtools::test()          # testthat suite (fixtures in inst/extdata)
```
```sh
R CMD build . && R CMD check --as-cran pdfsigner_*.tar.gz
```
pkgdown site is auto-built/deployed to **gh-pages** by
`.github/workflows/pkgdown.yaml` (uses the GitHub-installed `tidytemplate`,
pinned to a SHA) → https://strategicprojects.github.io/pdfsigner/

## Gotchas (hard-won)
- The extendr **module name MUST equal the package name** (`R_init_pdfsigner`),
  and `src/entrypoint.c` must reference `R_init_pdfsigner_extendr`.
- **Do NOT regenerate wrappers at install time.** The Makevars must only
  `cargo build --lib`; running `cargo run --bin document` during `R CMD INSTALL`
  breaks the Windows/CRAN build (the wrappers are committed; regen with
  `rextendr::document()` in dev only).
- Re-vendoring: `cd src/rust && cargo vendor vendor && tar -cJf vendor.tar.xz vendor`
  (config is `vendor-config.toml`, identical to cargo's output).
- macOS local `R CMD check` shows benign env-only messages (linker SDK warning,
  missing checkbashisms/HTML Tidy) that don't occur on CRAN.

## To sync a new pdf_signer version
Copy `pdf_signer/src/*.rs` → `src/rust/pdf_signer/src/` (EXCEPT `main.rs` — the
CLI/clap is not vendored), update the bundled `Cargo.toml` deps, re-vendor.

## Release
CRAN via `devtools::release()`; commit the `CRAN-SUBMISSION` record.
