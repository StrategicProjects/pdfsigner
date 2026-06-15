//! Signing path: insert a signature field + `adbe.pkcs7.detached` CMS signature.

use std::path::Path;

use der::Encode;
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};

use crate::crypto::cms_sign;
use crate::error::Error;
use crate::incremental::{last_startxref, Incremental};
use crate::util::{find_sub, hex_encode};
use crate::Result;

/// PAdES conformance level to produce.
///
/// Levels are cumulative: each adds material on top of the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PadesLevel {
    /// Baseline: CAdES `signing-certificate-v2`.
    #[default]
    Bb,
    /// B-B + an RFC 3161 signature timestamp (needs `tsa_url`).
    Bt,
    /// B-T + a Document Security Store (certificates + CRLs).
    Blt,
    /// B-LT + a document timestamp over the whole file (needs `tsa_url`).
    Blta,
}

/// A visible signature appearance, rendered as the widget's `/AP /N` stream.
///
/// Coordinates are in PDF user-space points (origin at the page's bottom-left).
/// The box occupies `[x, y, x + width, y + height]` on page `page` (1-based).
#[derive(Debug, Clone)]
pub struct Appearance {
    /// 1-based page number the signature box is drawn on.
    pub page: usize,
    /// Lower-left X of the box, in points.
    pub x: f64,
    /// Lower-left Y of the box, in points.
    pub y: f64,
    /// Box width, in points.
    pub width: f64,
    /// Box height, in points.
    pub height: f64,
    /// Font size, in points.
    pub font_size: f64,
    /// Text to render. Wrapped to the box width; `\n` forces a line break.
    pub text: String,
    /// Draw a thin rectangle border around the box.
    pub border: bool,
    /// Optional TrueType/OpenType font to embed (a simple WinAnsi font). When
    /// `None`, the standard Helvetica is used.
    pub font: Option<Vec<u8>>,
    /// Optional logo image (PNG or JPEG) drawn in the box.
    pub image: Option<Vec<u8>>,
    /// Image placement `[x, y, width, height]` in box points. When `None`, the
    /// image is drawn as a square on the left, sized to the box height.
    pub image_rect: Option<[f64; 4]>,
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            page: 1,
            x: 36.0,
            y: 36.0,
            width: 260.0,
            height: 70.0,
            font_size: 8.0,
            text: String::new(),
            border: true,
            font: None,
            image: None,
            image_rect: None,
        }
    }
}

/// Options controlling the signature dictionary metadata.
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Bytes reserved for the CMS blob inside `/Contents`. The hex placeholder
    /// is twice this size. Must exceed the produced signature length.
    pub signature_capacity: usize,
    /// Optional `/Reason` for signing.
    pub reason: Option<String>,
    /// Optional human `/Name` of the signer.
    pub name: Option<String>,
    /// Optional `/Location`.
    pub location: Option<String>,
    /// Optional `/ContactInfo`.
    pub contact_info: Option<String>,
    /// Optional signing time, already formatted as a PDF date, e.g.
    /// `D:20260614120000Z`.
    pub signing_time: Option<String>,
    /// Optional visible appearance. When `None`, the signature is invisible
    /// (zero-area widget).
    pub appearance: Option<Appearance>,
    /// Optional RFC 3161 Time-Stamping Authority `http://` URL. Required for
    /// `PadesLevel::Bt` and above.
    pub tsa_url: Option<String>,
    /// Target PAdES conformance level.
    pub pades_level: PadesLevel,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            // Generous: must fit the CMS plus, optionally, an RFC 3161
            // timestamp token (which carries the TSA certificate chain).
            signature_capacity: 30000,
            reason: None,
            name: None,
            location: None,
            contact_info: None,
            signing_time: None,
            appearance: None,
            tsa_url: None,
            pades_level: PadesLevel::Bb,
        }
    }
}

/// Sign `input` PDF, writing the signed PDF to `output`.
pub fn sign_pdf_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    keystore: impl AsRef<Path>,
    password: &str,
    opts: &SignOptions,
) -> Result<()> {
    let pdf = std::fs::read(input)?;
    let p12 = std::fs::read(keystore)?;
    let signed = sign_pdf_bytes(&pdf, &p12, password, opts)?;
    std::fs::write(output, signed)?;
    Ok(())
}

/// Sign an in-memory PDF with an in-memory PKCS#12 keystore.
pub fn sign_pdf_bytes(
    pdf: &[u8],
    keystore_p12: &[u8],
    password: &str,
    opts: &SignOptions,
) -> Result<Vec<u8>> {
    // 1. Build an incremental update (keeps the original bytes verbatim, so any
    //    prior signature stays valid).
    let mut buf = build_incremental_update(pdf, opts)?;

    // Our new placeholders live in the appended region; search from there so we
    // never hit a previous signature's already-filled /ByteRange or /Contents.
    let search_from = pdf.len();

    // 3. Locate the /Contents placeholder (the hex string of zeros).
    let (lt, gt) = locate_contents_placeholder(&buf, opts.signature_capacity, search_from)?;
    let p = lt; // index of '<'
    let q = gt + 1; // index just after '>'
    let total = buf.len();

    // 4. Patch the /ByteRange in place (length-preserving, so p/q stay valid).
    patch_byte_range(&mut buf, search_from, p as i64, q as i64, (total - q) as i64)?;

    // 5. Build the detached CMS over everything except the Contents hole.
    let mut signed_bytes = Vec::with_capacity(p + (total - q));
    signed_bytes.extend_from_slice(&buf[..p]);
    signed_bytes.extend_from_slice(&buf[q..]);
    // A signature timestamp (B-T+) needs a TSA; B-B does not.
    let sig_tsa = (opts.pades_level >= PadesLevel::Bt)
        .then_some(opts.tsa_url.as_deref())
        .flatten();
    let der = cms_sign(keystore_p12, password, &signed_bytes, sig_tsa)?;

    // 6. Write the signature hex into the placeholder.
    let hex = hex_encode(&der);
    let capacity_hex = opts.signature_capacity * 2;
    if hex.len() > capacity_hex {
        return Err(Error::PlaceholderTooSmall {
            needed: der.len(),
            capacity: opts.signature_capacity,
        });
    }
    let region = &mut buf[lt + 1..lt + 1 + capacity_hex];
    for b in region.iter_mut() {
        *b = b'0';
    }
    region[..hex.len()].copy_from_slice(&hex);

    // 7. PAdES-B-LT: add a Document Security Store with the validation material.
    if opts.pades_level >= PadesLevel::Blt {
        let material = crate::dss::collect_validation_material(&der)?;
        buf = crate::dss::add_dss(&buf, &material)?;
    }

    // 8. PAdES-B-LTA: add a document timestamp over the whole file (incl. DSS).
    if opts.pades_level >= PadesLevel::Blta {
        let url = opts
            .tsa_url
            .as_deref()
            .ok_or_else(|| Error::Crypto("PAdES-B-LTA requires a tsa_url".into()))?;
        buf = add_document_timestamp(&buf, url, opts.signature_capacity)?;
    }

    Ok(buf)
}

/// Add a document timestamp (`/DocTimeStamp`, `/SubFilter /ETSI.RFC3161`) over
/// the whole file as an incremental update — the archival anchor of PAdES-B-LTA.
fn add_document_timestamp(pdf: &[u8], tsa_url: &str, capacity: usize) -> Result<Vec<u8>> {
    let mut buf = build_doctimestamp_update(pdf, capacity)?;

    let start = pdf.len();
    let (lt, gt) = locate_contents_placeholder(&buf, capacity, start)?;
    let p = lt;
    let q = gt + 1;
    let total = buf.len();
    patch_byte_range(&mut buf, start, p as i64, q as i64, (total - q) as i64)?;

    let mut signed = Vec::with_capacity(p + (total - q));
    signed.extend_from_slice(&buf[..p]);
    signed.extend_from_slice(&buf[q..]);

    // The timestamp imprint is over the document byte range itself.
    let token = crate::tsa::request_timestamp(tsa_url, &signed)?;
    let token_der = token.to_der().map_err(|e| Error::Malformed(e.to_string()))?;

    let hex = hex_encode(&token_der);
    let capacity_hex = capacity * 2;
    if hex.len() > capacity_hex {
        return Err(Error::PlaceholderTooSmall {
            needed: token_der.len(),
            capacity,
        });
    }
    let region = &mut buf[lt + 1..lt + 1 + capacity_hex];
    for b in region.iter_mut() {
        *b = b'0';
    }
    region[..hex.len()].copy_from_slice(&hex);
    Ok(buf)
}

/// Incremental update carrying an empty `/DocTimeStamp` signature field.
fn build_doctimestamp_update(pdf: &[u8], capacity: usize) -> Result<Vec<u8>> {
    let doc = Document::load_mem(pdf)?;
    let root_id = doc.trailer.get(b"Root")?.as_reference()?;
    let page_id = nth_page_id(&doc, 1)?;

    let mut inc = Incremental::new(pdf);
    let mut next_id = doc.max_id + 1;
    let mut alloc = || {
        let id = (next_id, 0u16);
        next_id += 1;
        id
    };

    let ts_id = alloc();
    inc.add(ts_id, build_doctimestamp_dict(capacity));
    let widget_id = alloc();
    // Reuse the invisible-widget builder (no appearance), pointing at the TS dict.
    inc.add(widget_id, build_widget(&SignOptions::default(), ts_id, None));

    apply_widget_to_page(&doc, &mut inc, page_id, widget_id)?;
    apply_field_to_acroform(&doc, &mut inc, root_id, widget_id)?;

    let size = next_id;
    let prev = last_startxref(pdf)
        .ok_or_else(|| Error::Malformed("original PDF has no startxref".into()))?;
    let id_array = doc.trailer.get(b"ID").ok().cloned();
    Ok(inc.render(size, root_id, prev, id_array))
}

/// The `/DocTimeStamp` dictionary with ByteRange/Contents placeholders.
fn build_doctimestamp_dict(capacity: usize) -> Object {
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"DocTimeStamp".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"ETSI.RFC3161".to_vec()));
    sig.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(9_999_999_999),
            Object::Integer(9_999_999_999),
            Object::Integer(9_999_999_999),
        ]),
    );
    sig.set(
        "Contents",
        Object::String(vec![0u8; capacity], StringFormat::Hexadecimal),
    );
    Object::Dictionary(sig)
}

/// Assemble the incremental-update section (with signature placeholders) and
/// return `original_bytes + update`.
/// Allocate the next object id (generation 0) and advance the counter.
fn alloc_id(next_id: &mut u32) -> ObjectId {
    let id = (*next_id, 0u16);
    *next_id += 1;
    id
}

fn build_incremental_update(pdf: &[u8], opts: &SignOptions) -> Result<Vec<u8>> {
    let doc = Document::load_mem(pdf)?;
    let root_id = doc.trailer.get(b"Root")?.as_reference()?;
    let page_number = opts.appearance.as_ref().map(|a| a.page).unwrap_or(1);
    let page_id = nth_page_id(&doc, page_number)?;

    let mut inc = Incremental::new(pdf);
    let mut next_id = doc.max_id + 1;

    let sig_id = alloc_id(&mut next_id);
    inc.add(sig_id, build_sig_dict(opts));

    // Optional visible appearance (font, image, Form XObject).
    let mut ap_ref = None;
    if let Some(app) = &opts.appearance {
        ap_ref = Some(crate::appearance::add_appearance(&mut inc, &mut next_id, app)?);
    }

    let widget_id = alloc_id(&mut next_id);
    inc.add(widget_id, build_widget(opts, sig_id, ap_ref));

    apply_widget_to_page(&doc, &mut inc, page_id, widget_id)?;
    apply_field_to_acroform(&doc, &mut inc, root_id, widget_id)?;

    let size = next_id; // highest object id allocated + 1
    let prev = last_startxref(pdf)
        .ok_or_else(|| Error::Malformed("original PDF has no startxref".into()))?;
    let id_array = doc.trailer.get(b"ID").ok().cloned();

    Ok(inc.render(size, root_id, prev, id_array))
}

/// The signature `/Sig` dictionary, with ByteRange/Contents placeholders.
fn build_sig_dict(opts: &SignOptions) -> Object {
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"Sig".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"ETSI.CAdES.detached".to_vec()));
    // Ten-digit sentinels reserve enough width for any realistic file offset.
    sig.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(9_999_999_999),
            Object::Integer(9_999_999_999),
            Object::Integer(9_999_999_999),
        ]),
    );
    sig.set(
        "Contents",
        Object::String(vec![0u8; opts.signature_capacity], StringFormat::Hexadecimal),
    );
    if let Some(r) = &opts.reason {
        sig.set("Reason", Object::string_literal(r.clone()));
    }
    if let Some(n) = &opts.name {
        sig.set("Name", Object::string_literal(n.clone()));
    }
    if let Some(l) = &opts.location {
        sig.set("Location", Object::string_literal(l.clone()));
    }
    if let Some(c) = &opts.contact_info {
        sig.set("ContactInfo", Object::string_literal(c.clone()));
    }
    if let Some(t) = &opts.signing_time {
        sig.set("M", Object::string_literal(t.clone()));
    }
    Object::Dictionary(sig)
}

/// The `/FT /Sig` widget annotation referencing the signature dictionary.
fn build_widget(opts: &SignOptions, sig_id: ObjectId, ap_ref: Option<ObjectId>) -> Object {
    let mut field = Dictionary::new();
    field.set("Type", Object::Name(b"Annot".to_vec()));
    field.set("Subtype", Object::Name(b"Widget".to_vec()));
    field.set("FT", Object::Name(b"Sig".to_vec()));
    // Field name must be unique across (re-)signatures; key it to the sig id.
    field.set("T", Object::string_literal(format!("Signature{}", sig_id.0)));
    field.set("F", Object::Integer(132)); // Print | Locked
    field.set("V", Object::Reference(sig_id));

    match (&opts.appearance, ap_ref) {
        (Some(app), Some(ap_id)) => {
            field.set(
                "Rect",
                rect_array(app.x, app.y, app.x + app.width, app.y + app.height),
            );
            let mut ap = Dictionary::new();
            ap.set("N", Object::Reference(ap_id));
            field.set("AP", Object::Dictionary(ap));
        }
        _ => {
            // Invisible signature: zero-area rectangle.
            field.set("Rect", rect_array(0.0, 0.0, 0.0, 0.0));
        }
    }
    Object::Dictionary(field)
}

fn rect_array(x1: f64, y1: f64, x2: f64, y2: f64) -> Object {
    Object::Array(vec![
        Object::Real(x1 as f32),
        Object::Real(y1 as f32),
        Object::Real(x2 as f32),
        Object::Real(y2 as f32),
    ])
}

/// First object id of page `page_number` (1-based), falling back to page 1.
fn nth_page_id(doc: &Document, page_number: usize) -> Result<ObjectId> {
    let pages = doc.get_pages();
    pages
        .get(&(page_number as u32))
        .copied()
        .or_else(|| pages.values().next().copied())
        .ok_or_else(|| Error::Malformed("PDF has no pages".into()))
}

/// Add the widget to the target page's `/Annots`, re-emitting only what changed.
fn apply_widget_to_page(
    doc: &Document,
    inc: &mut Incremental,
    page_id: ObjectId,
    widget_id: ObjectId,
) -> Result<()> {
    let page = doc.get_object(page_id)?.as_dict()?;
    let widget_ref = Object::Reference(widget_id);
    match page.get(b"Annots") {
        Ok(Object::Reference(r)) => {
            // Annots is its own object — modify just that array.
            let r = *r;
            let mut arr = doc.get_object(r)?.as_array()?.clone();
            arr.push(widget_ref);
            inc.add(r, Object::Array(arr));
        }
        Ok(Object::Array(a)) => {
            let mut page = page.clone();
            let mut arr = a.clone();
            arr.push(widget_ref);
            page.set("Annots", Object::Array(arr));
            inc.add(page_id, Object::Dictionary(page));
        }
        _ => {
            let mut page = page.clone();
            page.set("Annots", Object::Array(vec![widget_ref]));
            inc.add(page_id, Object::Dictionary(page));
        }
    }
    Ok(())
}

/// Register the field in `/AcroForm` (creating it if absent), re-emitting only
/// the object that actually changes.
fn apply_field_to_acroform(
    doc: &Document,
    inc: &mut Incremental,
    root_id: ObjectId,
    widget_id: ObjectId,
) -> Result<()> {
    let catalog = doc.get_object(root_id)?.as_dict()?;
    let widget_ref = Object::Reference(widget_id);

    match catalog.get(b"AcroForm") {
        Ok(Object::Reference(af)) => {
            let af = *af;
            let mut form = doc.get_object(af)?.as_dict()?.clone();
            add_field_to_form(doc, inc, &mut form, widget_ref)?;
            form.set("SigFlags", Object::Integer(3));
            inc.add(af, Object::Dictionary(form));
        }
        Ok(Object::Dictionary(d)) => {
            let mut catalog = catalog.clone();
            let mut form = d.clone();
            add_field_to_form(doc, inc, &mut form, widget_ref)?;
            form.set("SigFlags", Object::Integer(3));
            catalog.set("AcroForm", Object::Dictionary(form));
            inc.add(root_id, Object::Dictionary(catalog));
        }
        _ => {
            let mut catalog = catalog.clone();
            let mut form = Dictionary::new();
            form.set("Fields", Object::Array(vec![widget_ref]));
            form.set("SigFlags", Object::Integer(3));
            catalog.set("AcroForm", Object::Dictionary(form));
            inc.add(root_id, Object::Dictionary(catalog));
        }
    }
    Ok(())
}

/// Append `widget_ref` to a form's `/Fields`, handling both an inline array and
/// a referenced array object.
fn add_field_to_form(
    doc: &Document,
    inc: &mut Incremental,
    form: &mut Dictionary,
    widget_ref: Object,
) -> Result<()> {
    match form.get(b"Fields") {
        Ok(Object::Reference(fr)) => {
            let fr = *fr;
            let mut arr = doc.get_object(fr)?.as_array()?.clone();
            arr.push(widget_ref);
            inc.add(fr, Object::Array(arr));
        }
        Ok(Object::Array(a)) => {
            let mut arr = a.clone();
            arr.push(widget_ref);
            form.set("Fields", Object::Array(arr));
        }
        _ => {
            form.set("Fields", Object::Array(vec![widget_ref]));
        }
    }
    Ok(())
}
/// Find the `< 00..00 >` placeholder at or after `start`, returning the `<` and
/// `>` indices. `start` skips any prior (already-filled) signature.
fn locate_contents_placeholder(
    buf: &[u8],
    capacity: usize,
    start: usize,
) -> Result<(usize, usize)> {
    // Search after /ByteRange so we never collide with a page's /Contents.
    let br = start
        + find_sub(&buf[start..], b"/ByteRange")
            .ok_or_else(|| Error::Malformed("/ByteRange not found".into()))?;
    let rel = find_sub(&buf[br..], b"/Contents")
        .ok_or_else(|| Error::Malformed("/Contents not found".into()))?;
    let from = br + rel;
    let lt_rel = find_sub(&buf[from..], b"<")
        .ok_or_else(|| Error::Malformed("Contents '<' not found".into()))?;
    let lt = from + lt_rel;
    let gt = lt + 1 + capacity * 2;
    if gt >= buf.len() || buf[gt] != b'>' {
        return Err(Error::Malformed(
            "Contents placeholder size mismatch".into(),
        ));
    }
    Ok((lt, gt))
}

/// Replace the `/ByteRange [...]` array (at or after `start`) with concrete
/// offsets, padding with spaces so the byte length is unchanged.
fn patch_byte_range(buf: &mut [u8], start: usize, a: i64, b: i64, c: i64) -> Result<()> {
    let br = start
        + find_sub(&buf[start..], b"/ByteRange")
            .ok_or_else(|| Error::Malformed("/ByteRange not found".into()))?;
    let open = br + find_sub(&buf[br..], b"[")
        .ok_or_else(|| Error::Malformed("ByteRange '[' not found".into()))?;
    let close = open
        + find_sub(&buf[open..], b"]").ok_or_else(|| Error::Malformed("ByteRange ']' not found".into()))?;
    let span = close - open + 1;
    let mut replacement = format!("[0 {} {} {}]", a, b, c).into_bytes();
    if replacement.len() > span {
        return Err(Error::Malformed("ByteRange placeholder too small".into()));
    }
    // Pad with spaces just before the closing ']'.
    while replacement.len() < span {
        replacement.insert(replacement.len() - 1, b' ');
    }
    buf[open..=close].copy_from_slice(&replacement);
    Ok(())
}
