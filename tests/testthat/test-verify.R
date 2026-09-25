test_that("an unsigned PDF reports no signatures", {
  expect_length(verify_pdf_signature(sample_pdf()), 0)
})

test_that("a tampered signed document fails verification", {
  out <- tempfile(fileext = ".pdf")
  on.exit(unlink(out), add = TRUE)

  sign_pdf(sample_pdf(), out, keystore(), keystore_pw)
  expect_true(verify_pdf_signature(out)[[1]]$valid)

  # Flip a byte inside the first signed segment to break the digest.
  raw <- readBin(out, "raw", file.size(out))
  raw[200] <- as.raw(bitwXor(as.integer(raw[200]), 0xFFL))
  writeBin(raw, out)

  expect_false(verify_pdf_signature(out)[[1]]$valid)
})

test_that("an unsigned change after signing breaks document integrity", {
  out <- tempfile(fileext = ".pdf")
  on.exit(unlink(out), add = TRUE)
  sign_pdf(sample_pdf(), out, keystore(), keystore_pw)

  sigs <- verify_pdf_signature(out)
  expect_true(attr(sigs, "document_intact"))
  expect_true(attr(sigs, "all_valid"))
  expect_false(attr(sigs, "all_trusted"))  # no roots supplied
  expect_false(sigs[[1]]$is_timestamp)
  expect_true(is.na(sigs[[1]]$trusted_time))

  # Append bytes that are not a signed revision: the signature over the
  # original bytes still verifies, but the document is no longer intact.
  con <- file(out, open = "ab")
  writeBin(charToRaw("\n% appended after signing\n"), con)
  close(con)
  tampered <- verify_pdf_signature(out)
  expect_true(tampered[[1]]$valid)
  expect_false(tampered[[1]]$covers_whole_document)
  expect_false(attr(tampered, "document_intact"))
  expect_false(attr(tampered, "all_valid"))
})
