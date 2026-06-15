//! Rich visible-signature appearances: embedded TrueType fonts and PNG/JPEG
//! logos, plus the appearance content stream.
//!
//! Font embedding is a *simple* WinAnsi TrueType font (Latin-1); full Unicode
//! (Type0 / CID) is not implemented.

use lopdf::{Dictionary, Object, ObjectId, Stream};

use crate::error::Error;
use crate::incremental::{zlib_compress, Incremental};
use crate::sign::Appearance;
use crate::Result;

fn err<E: std::fmt::Display>(e: E) -> Error {
    Error::Malformed(e.to_string())
}

fn name(s: &[u8]) -> Object {
    Object::Name(s.to_vec())
}

fn real(v: f64) -> Object {
    Object::Real(v as f32)
}

/// Build every object the appearance needs (font, optional image + soft mask,
/// and the Form XObject), add them to `inc`, and return the Form XObject id.
pub(crate) fn add_appearance(
    inc: &mut Incremental,
    next_id: &mut u32,
    app: &Appearance,
) -> Result<ObjectId> {
    let mut alloc = || {
        let id = (*next_id, 0u16);
        *next_id += 1;
        id
    };

    // --- font ---
    let font_id = alloc();
    let font_name: &[u8] = if let Some(bytes) = &app.font {
        let descriptor_id = alloc();
        let fontfile_id = alloc();
        let (font_dict, descriptor, fontfile) =
            build_embedded_font(bytes, descriptor_id, fontfile_id)?;
        inc.add(font_id, font_dict);
        inc.add(descriptor_id, descriptor);
        inc.add(fontfile_id, fontfile);
        b"EmbFont"
    } else {
        inc.add(font_id, helvetica());
        b"Helv"
    };

    // --- image ---
    let mut image: Option<(ObjectId, [f64; 4])> = None;
    if let Some(bytes) = &app.image {
        let img = decode_image(bytes)?;
        let smask_ref = img.smask.as_ref().map(|sm| {
            let sid = alloc();
            inc.add(sid, image_stream(img.width, img.height, b"DeviceGray", b"FlateDecode", sm.clone(), None));
            sid
        });
        let img_id = alloc();
        inc.add(
            img_id,
            image_stream(img.width, img.height, img.color_space, img.filter, img.data, smask_ref),
        );
        let h = app.height - 4.0;
        let rect = app.image_rect.unwrap_or([2.0, 2.0, h.min(app.width - 4.0), h]);
        image = Some((img_id, rect));
    }

    // --- Form XObject ---
    let mut resources = Dictionary::new();
    let mut fonts = Dictionary::new();
    fonts.set(font_name.to_vec(), Object::Reference(font_id));
    resources.set("Font", Object::Dictionary(fonts));
    if let Some((img_id, _)) = image {
        let mut xobjects = Dictionary::new();
        xobjects.set("Img", Object::Reference(img_id));
        resources.set("XObject", Object::Dictionary(xobjects));
    }

    let mut xobj = Dictionary::new();
    xobj.set("Type", name(b"XObject"));
    xobj.set("Subtype", name(b"Form"));
    xobj.set("FormType", Object::Integer(1));
    xobj.set(
        "BBox",
        Object::Array(vec![real(0.0), real(0.0), real(app.width), real(app.height)]),
    );
    xobj.set("Resources", Object::Dictionary(resources));

    let content = build_content(app, font_name, image.map(|(_, r)| r));
    let xobj_id = alloc();
    inc.add(xobj_id, Object::Stream(Stream::new(xobj, content)));
    Ok(xobj_id)
}

/// Standard (non-embedded) Helvetica.
fn helvetica() -> Object {
    let mut f = Dictionary::new();
    f.set("Type", name(b"Font"));
    f.set("Subtype", name(b"Type1"));
    f.set("BaseFont", name(b"Helvetica"));
    f.set("Encoding", name(b"WinAnsiEncoding"));
    Object::Dictionary(f)
}

// --- embedded TrueType font (simple, WinAnsi) --------------------------------

fn build_embedded_font(
    bytes: &[u8],
    descriptor_id: ObjectId,
    fontfile_id: ObjectId,
) -> Result<(Object, Object, Object)> {
    let face = ttf_parser::Face::parse(bytes, 0).map_err(err)?;
    let upem = face.units_per_em() as f64;
    let scale = 1000.0 / upem;

    // Per-character advance widths for the WinAnsi range 32..=255.
    let mut widths = Vec::with_capacity(224);
    for b in 32u32..=255 {
        let advance = char::from_u32(b)
            .and_then(|c| face.glyph_index(c))
            .and_then(|g| face.glyph_hor_advance(g))
            .unwrap_or(0);
        widths.push(Object::Integer((advance as f64 * scale).round() as i64));
    }

    let bbox = face.global_bounding_box();
    let font_bbox = Object::Array(vec![
        Object::Integer((bbox.x_min as f64 * scale).round() as i64),
        Object::Integer((bbox.y_min as f64 * scale).round() as i64),
        Object::Integer((bbox.x_max as f64 * scale).round() as i64),
        Object::Integer((bbox.y_max as f64 * scale).round() as i64),
    ]);
    let italic = face.italic_angle();
    let mut flags = 32; // Nonsymbolic
    if italic != 0.0 {
        flags |= 64;
    }

    let mut descriptor = Dictionary::new();
    descriptor.set("Type", name(b"FontDescriptor"));
    descriptor.set("FontName", name(b"EmbeddedFont"));
    descriptor.set("Flags", Object::Integer(flags));
    descriptor.set("FontBBox", font_bbox);
    descriptor.set("ItalicAngle", real(italic as f64));
    descriptor.set("Ascent", Object::Integer((face.ascender() as f64 * scale).round() as i64));
    descriptor.set("Descent", Object::Integer((face.descender() as f64 * scale).round() as i64));
    descriptor.set(
        "CapHeight",
        Object::Integer(
            (face.capital_height().unwrap_or(face.ascender()) as f64 * scale).round() as i64,
        ),
    );
    descriptor.set("StemV", Object::Integer(80));
    descriptor.set("FontFile2", Object::Reference(fontfile_id));

    // The font program, FlateDecode'd, with /Length1 = uncompressed size.
    let mut ff_dict = Dictionary::new();
    ff_dict.set("Length1", Object::Integer(bytes.len() as i64));
    ff_dict.set("Filter", name(b"FlateDecode"));
    let fontfile = Object::Stream(Stream::new(ff_dict, zlib_compress(bytes)));

    let mut font = Dictionary::new();
    font.set("Type", name(b"Font"));
    font.set("Subtype", name(b"TrueType"));
    font.set("BaseFont", name(b"EmbeddedFont"));
    font.set("FirstChar", Object::Integer(32));
    font.set("LastChar", Object::Integer(255));
    font.set("Widths", Object::Array(widths));
    font.set("Encoding", name(b"WinAnsiEncoding"));
    font.set("FontDescriptor", Object::Reference(descriptor_id));

    Ok((Object::Dictionary(font), Object::Dictionary(descriptor), fontfile))
}

// --- image embedding ---------------------------------------------------------

struct EmbeddedImage {
    width: u32,
    height: u32,
    color_space: &'static [u8],
    filter: &'static [u8],
    data: Vec<u8>,
    smask: Option<Vec<u8>>, // FlateDecode'd grayscale alpha
}

fn decode_image(bytes: &[u8]) -> Result<EmbeddedImage> {
    if bytes.starts_with(&[0xFF, 0xD8]) {
        decode_jpeg(bytes)
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        decode_png(bytes)
    } else {
        Err(Error::Malformed("unsupported image format (use PNG or JPEG)".into()))
    }
}

/// JPEG: embed the bytes directly as DCTDecode; parse the SOF for dimensions.
fn decode_jpeg(bytes: &[u8]) -> Result<EmbeddedImage> {
    let mut i = 2;
    while i + 9 < bytes.len() {
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = bytes[i + 1];
        // SOF0..SOF15 except DHT(C4), JPG(C8), DAC(CC) carry the frame header.
        if (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC {
            let height = u16::from_be_bytes([bytes[i + 5], bytes[i + 6]]) as u32;
            let width = u16::from_be_bytes([bytes[i + 7], bytes[i + 8]]) as u32;
            let components = bytes[i + 9];
            let cs: &[u8] = if components == 1 { b"DeviceGray" } else { b"DeviceRGB" };
            return Ok(EmbeddedImage {
                width,
                height,
                color_space: cs,
                filter: b"DCTDecode",
                data: bytes.to_vec(),
                smask: None,
            });
        }
        // Skip this segment using its length.
        if i + 3 >= bytes.len() {
            break;
        }
        let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        i += 2 + len;
    }
    Err(Error::Malformed("could not parse JPEG dimensions".into()))
}

/// PNG: decode to 8-bit samples, split colour and alpha, embed FlateDecode'd.
fn decode_png(bytes: &[u8]) -> Result<EmbeddedImage> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(err)?;
    let size = reader
        .output_buffer_size()
        .ok_or_else(|| Error::Malformed("PNG dimensions too large".into()))?;
    let mut buf = vec![0u8; size];
    let info = reader.next_frame(&mut buf).map_err(err)?;
    buf.truncate(info.buffer_size());
    let (w, h) = (info.width, info.height);
    let px = (w * h) as usize;

    let (color_space, color, alpha): (&[u8], Vec<u8>, Option<Vec<u8>>) = match info.color_type {
        png::ColorType::Rgb => (b"DeviceRGB", buf, None),
        png::ColorType::Grayscale => (b"DeviceGray", buf, None),
        png::ColorType::Rgba => {
            let mut rgb = Vec::with_capacity(px * 3);
            let mut a = Vec::with_capacity(px);
            for p in buf.chunks_exact(4) {
                rgb.extend_from_slice(&p[..3]);
                a.push(p[3]);
            }
            (b"DeviceRGB", rgb, Some(a))
        }
        png::ColorType::GrayscaleAlpha => {
            let mut g = Vec::with_capacity(px);
            let mut a = Vec::with_capacity(px);
            for p in buf.chunks_exact(2) {
                g.push(p[0]);
                a.push(p[1]);
            }
            (b"DeviceGray", g, Some(a))
        }
        png::ColorType::Indexed => {
            return Err(Error::Malformed("indexed PNG not expanded".into()))
        }
    };

    Ok(EmbeddedImage {
        width: w,
        height: h,
        color_space,
        filter: b"FlateDecode",
        data: zlib_compress(&color),
        smask: alpha.map(|a| zlib_compress(&a)),
    })
}

fn image_stream(
    width: u32,
    height: u32,
    color_space: &[u8],
    filter: &[u8],
    data: Vec<u8>,
    smask: Option<ObjectId>,
) -> Object {
    let mut d = Dictionary::new();
    d.set("Type", name(b"XObject"));
    d.set("Subtype", name(b"Image"));
    d.set("Width", Object::Integer(width as i64));
    d.set("Height", Object::Integer(height as i64));
    d.set("ColorSpace", name(color_space));
    d.set("BitsPerComponent", Object::Integer(8));
    d.set("Filter", name(filter));
    if let Some(sm) = smask {
        d.set("SMask", Object::Reference(sm));
    }
    Object::Stream(Stream::new(d, data))
}

// --- content stream ----------------------------------------------------------

/// Render the appearance: optional image, optional border, wrapped text.
fn build_content(app: &Appearance, font_name: &[u8], image: Option<[f64; 4]>) -> Vec<u8> {
    let margin = 2.0_f64;
    let fs = app.font_size;
    let leading = fs * 1.2;
    let max_w = (app.width - 2.0 * margin).max(1.0);
    let lines = wrap_text(&app.text, max_w, fs);
    let start_y = app.height - margin - fs;

    let mut out: Vec<u8> = Vec::new();

    if let Some([ix, iy, iw, ih]) = image {
        out.extend_from_slice(
            format!("q {:.2} 0 0 {:.2} {:.2} {:.2} cm /Img Do Q\n", iw, ih, ix, iy).as_bytes(),
        );
    }

    out.extend_from_slice(b"q\n");
    if app.border {
        out.extend_from_slice(
            format!(
                "0.5 0.5 0.5 RG 0.75 w 0.50 0.50 {:.2} {:.2} re S\n",
                app.width - 1.0,
                app.height - 1.0
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(b"0 0 0 rg\nBT\n");
    out.push(b'/');
    out.extend_from_slice(font_name);
    out.extend_from_slice(format!(" {:.2} Tf\n", fs).as_bytes());
    out.extend_from_slice(format!("{:.2} TL\n", leading).as_bytes());
    out.extend_from_slice(format!("{:.2} {:.2} Td\n", margin, start_y).as_bytes());
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"T* ");
        }
        out.push(b'(');
        out.extend_from_slice(&encode_winansi_escaped(line));
        out.extend_from_slice(b") Tj\n");
    }
    out.extend_from_slice(b"ET\nQ\n");
    out
}

/// Encode a line to WinAnsi bytes, escaping PDF literal-string specials.
fn encode_winansi_escaped(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 4);
    for ch in s.chars() {
        let b = if (ch as u32) <= 0xFF { ch as u8 } else { b'?' };
        if matches!(b, b'(' | b')' | b'\\') {
            v.push(b'\\');
        }
        v.push(b);
    }
    v
}

/// Greedy word-wrap using an approximate average glyph width (~0.5 em).
fn wrap_text(text: &str, max_width: f64, font_size: f64) -> Vec<String> {
    let char_w = (font_size * 0.5).max(0.1);
    let max_chars = ((max_width / char_w).floor() as usize).max(1);

    let mut out = Vec::new();
    for para in text.split('\n') {
        let para = para.trim_end();
        if para.is_empty() {
            out.push(String::new());
            continue;
        }
        let mut cur = String::new();
        for word in para.split_whitespace() {
            if cur.is_empty() {
                if word.chars().count() > max_chars {
                    let mut chunk = String::new();
                    for c in word.chars() {
                        if chunk.chars().count() >= max_chars {
                            out.push(std::mem::take(&mut chunk));
                        }
                        chunk.push(c);
                    }
                    cur = chunk;
                } else {
                    cur = word.to_string();
                }
            } else if cur.chars().count() + 1 + word.chars().count() <= max_chars {
                cur.push(' ');
                cur.push_str(word);
            } else {
                out.push(std::mem::take(&mut cur));
                cur = word.to_string();
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    out
}
