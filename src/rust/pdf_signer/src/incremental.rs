//! Incremental update writer.
//!
//! Instead of re-serializing the whole document (which would invalidate any
//! pre-existing signature), an incremental update keeps the original bytes
//! **verbatim** and appends:
//!   * the new / modified objects,
//!   * a fresh cross-reference table listing only those objects,
//!   * a trailer whose `/Prev` chains back to the previous xref.
//!
//! This is what makes multi-signature work: signing again only appends, so
//! earlier signatures keep covering an unchanged byte range.

use std::collections::BTreeMap;

use lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};

/// Accumulates the objects to append and renders the updated file.
pub(crate) struct Incremental<'a> {
    original: &'a [u8],
    objects: BTreeMap<u32, (u16, Object)>,
}

impl<'a> Incremental<'a> {
    pub(crate) fn new(original: &'a [u8]) -> Self {
        Self {
            original,
            objects: BTreeMap::new(),
        }
    }

    /// Queue an object (new or modified) for the update section.
    pub(crate) fn add(&mut self, id: ObjectId, obj: Object) {
        self.objects.insert(id.0, (id.1, obj));
    }

    /// Render `original + appended update`. `size` is the new `/Size`,
    /// `root` the catalog id, `prev` the previous `startxref` offset. Emits a
    /// cross-reference **stream** when the original uses one, otherwise a
    /// traditional cross-reference **table** — matching the source's convention.
    pub(crate) fn render(
        &self,
        size: u32,
        root: ObjectId,
        prev: usize,
        id_array: Option<Object>,
    ) -> Vec<u8> {
        if uses_xref_stream(self.original) {
            self.render_xref_stream(size, root, prev, id_array)
        } else {
            self.render_xref_table(size, root, prev, id_array)
        }
    }

    /// Traditional cross-reference table incremental update.
    fn render_xref_table(
        &self,
        size: u32,
        root: ObjectId,
        prev: usize,
        id_array: Option<Object>,
    ) -> Vec<u8> {
        let mut out = self.original.to_vec();
        if !out.ends_with(b"\n") {
            out.push(b'\n');
        }

        // 1. Emit the objects, recording absolute offsets.
        let mut entries: Vec<(u32, u16, usize)> = Vec::with_capacity(self.objects.len());
        for (&id, (gen, obj)) in &self.objects {
            let off = out.len();
            out.extend_from_slice(format!("{} {} obj\n", id, gen).as_bytes());
            write_object(&mut out, obj);
            out.extend_from_slice(b"\nendobj\n");
            entries.push((id, *gen, off));
        }

        // 2. Cross-reference table (entries are already sorted by id).
        let xref_off = out.len();
        out.extend_from_slice(b"xref\n");
        let mut i = 0;
        while i < entries.len() {
            let mut j = i;
            while j + 1 < entries.len() && entries[j + 1].0 == entries[j].0 + 1 {
                j += 1;
            }
            out.extend_from_slice(format!("{} {}\n", entries[i].0, j - i + 1).as_bytes());
            for e in &entries[i..=j] {
                // Each entry is exactly 20 bytes: "%010d %05d n\r\n".
                out.extend_from_slice(format!("{:010} {:05} n\r\n", e.2, e.1).as_bytes());
            }
            i = j + 1;
        }

        // 3. Trailer + startxref.
        out.extend_from_slice(b"trailer\n<< ");
        out.extend_from_slice(
            format!("/Size {} /Root {} {} R /Prev {}", size, root.0, root.1, prev).as_bytes(),
        );
        if let Some(id) = id_array {
            out.extend_from_slice(b" /ID ");
            write_object(&mut out, &id);
        }
        out.extend_from_slice(b" >>\nstartxref\n");
        out.extend_from_slice(format!("{}\n%%EOF\n", xref_off).as_bytes());
        out
    }

    /// Cross-reference **stream** incremental update (PDF 1.5+). The xref is a
    /// `/Type /XRef` stream object that also indexes itself.
    fn render_xref_stream(
        &self,
        size: u32,
        root: ObjectId,
        prev: usize,
        id_array: Option<Object>,
    ) -> Vec<u8> {
        let mut out = self.original.to_vec();
        if !out.ends_with(b"\n") {
            out.push(b'\n');
        }

        // Emit the objects, recording (id, gen, offset).
        let mut entries: Vec<(u32, u16, usize)> = Vec::with_capacity(self.objects.len() + 1);
        for (&id, (gen, obj)) in &self.objects {
            let off = out.len();
            out.extend_from_slice(format!("{} {} obj\n", id, gen).as_bytes());
            write_object(&mut out, obj);
            out.extend_from_slice(b"\nendobj\n");
            entries.push((id, *gen, off));
        }

        // The xref stream is itself an object; it indexes itself.
        let xref_id = size; // next free id
        let xref_off = out.len();
        entries.push((xref_id, 0, xref_off));
        entries.sort_by_key(|e| e.0);

        // Binary cross-reference with field widths W = [1, 4, 2].
        let mut data = Vec::with_capacity(entries.len() * 7);
        for (_, gen, off) in &entries {
            data.push(1u8); // type 1: in-use object
            data.extend_from_slice(&(*off as u32).to_be_bytes());
            data.extend_from_slice(&gen.to_be_bytes());
        }
        let compressed = zlib_compress(&data);

        // /Index subsections for the (sorted) object ids.
        let mut index = String::new();
        let mut i = 0;
        while i < entries.len() {
            let mut j = i;
            while j + 1 < entries.len() && entries[j + 1].0 == entries[j].0 + 1 {
                j += 1;
            }
            index.push_str(&format!("{} {} ", entries[i].0, j - i + 1));
            i = j + 1;
        }

        out.extend_from_slice(format!("{} 0 obj\n", xref_id).as_bytes());
        out.extend_from_slice(
            format!(
                "<< /Type /XRef /Size {} /Root {} {} R /Prev {} /W [1 4 2] /Index [{}]",
                xref_id + 1,
                root.0,
                root.1,
                prev,
                index.trim_end()
            )
            .as_bytes(),
        );
        if let Some(id) = id_array {
            out.extend_from_slice(b" /ID ");
            write_object(&mut out, &id);
        }
        out.extend_from_slice(
            format!(" /Filter /FlateDecode /Length {} >>\nstream\n", compressed.len()).as_bytes(),
        );
        out.extend_from_slice(&compressed);
        out.extend_from_slice(b"\nendstream\nendobj\n");

        out.extend_from_slice(b"startxref\n");
        out.extend_from_slice(format!("{}\n%%EOF\n", xref_off).as_bytes());
        out
    }
}

/// True if the file's most recent cross-reference is a stream (not an `xref`
/// table), i.e. `startxref` points at an object rather than the `xref` keyword.
fn uses_xref_stream(buf: &[u8]) -> bool {
    let Some(off) = last_startxref(buf) else {
        return false;
    };
    let mut i = off;
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    !buf[i..].starts_with(b"xref")
}

/// Zlib-compress (PDF `FlateDecode`).
pub(crate) fn zlib_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("zlib write");
    encoder.finish().expect("zlib finish")
}

/// Offset of the most recent `startxref` value in `buf` (the previous xref).
pub(crate) fn last_startxref(buf: &[u8]) -> Option<usize> {
    let needle = b"startxref";
    let pos = (0..=buf.len().saturating_sub(needle.len()))
        .rev()
        .find(|&i| &buf[i..i + needle.len()] == needle)?;
    let mut i = pos + needle.len();
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut n = 0usize;
    let mut any = false;
    while i < buf.len() && buf[i].is_ascii_digit() {
        n = n * 10 + (buf[i] - b'0') as usize;
        i += 1;
        any = true;
    }
    any.then_some(n)
}

// --- a minimal, byte-exact PDF object serializer ------------------------------

fn write_object(out: &mut Vec<u8>, obj: &Object) {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(r) => out.extend_from_slice(fmt_real(*r).as_bytes()),
        Object::Name(n) => write_name(out, n),
        Object::String(s, fmt) => write_string(out, s, *fmt),
        Object::Reference(id) => {
            out.extend_from_slice(format!("{} {} R", id.0, id.1).as_bytes())
        }
        Object::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(out, e);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => write_dict(out, d),
        Object::Stream(s) => write_stream(out, s),
    }
}

fn write_dict(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend_from_slice(b"<< ");
    for (k, v) in d.iter() {
        write_name(out, k);
        out.push(b' ');
        write_object(out, v);
        out.push(b' ');
    }
    out.extend_from_slice(b">>");
}

fn write_stream(out: &mut Vec<u8>, s: &Stream) {
    let mut dict = s.dict.clone();
    dict.set("Length", Object::Integer(s.content.len() as i64));
    write_dict(out, &dict);
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(&s.content);
    out.extend_from_slice(b"\nendstream");
}

fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &b in name {
        let regular = (0x21..0x7f).contains(&b)
            && !matches!(
                b,
                b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%' | b'#'
            );
        if regular {
            out.push(b);
        } else {
            out.extend_from_slice(format!("#{:02X}", b).as_bytes());
        }
    }
}

fn write_string(out: &mut Vec<u8>, s: &[u8], fmt: StringFormat) {
    match fmt {
        StringFormat::Hexadecimal => {
            out.push(b'<');
            for &b in s {
                out.extend_from_slice(format!("{:02x}", b).as_bytes());
            }
            out.push(b'>');
        }
        StringFormat::Literal => {
            out.push(b'(');
            for &b in s {
                match b {
                    b'(' | b')' | b'\\' => {
                        out.push(b'\\');
                        out.push(b);
                    }
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    _ => out.push(b),
                }
            }
            out.push(b')');
        }
    }
}

/// Format a real without scientific notation (PDF forbids it).
fn fmt_real(r: f32) -> String {
    if r.is_finite() && r == r.trunc() {
        format!("{}", r as i64)
    } else {
        let s = format!("{r}");
        if s.contains(['e', 'E']) {
            format!("{r:.6}")
        } else {
            s
        }
    }
}
