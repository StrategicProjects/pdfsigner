//! Test/demo helpers: build a minimal sample PDF and a self-signed PKCS#12.
//!
//! These exist so the PoC is fully reproducible without external fixtures and
//! without OpenSSL — everything is pure RustCrypto. They are not part of the
//! production signing/verification surface.

use std::str::FromStr;
use std::time::Duration;

use lopdf::content::{Content, Operation};
use lopdf::{dictionary, Document, Object, Stream};

use const_oid::ObjectIdentifier;
use der::Encode;
use p12_keystore::{Certificate as P12Certificate, KeyStore, KeyStoreEntry, PrivateKeyChain};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use signature::Keypair;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

/// Build a minimal, valid one-page PDF with a line of text.
pub fn sample_pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();

    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! { "F1" => font_id },
    });

    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 24.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "Tj",
                vec![Object::string_literal("pdf_signer PoC - sample document")],
            ),
            Operation::new("ET", vec![]),
        ],
    };
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));

    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Resources" => resources_id,
    });

    let pages = dictionary! {
        "Type" => "Pages",
        "Kids" => vec![page_id.into()],
        "Count" => 1,
    };
    doc.objects.insert(pages_id, Object::Dictionary(pages));

    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);

    let mut buf = Vec::new();
    doc.save_to(&mut buf).unwrap();
    buf
}

/// Build a self-signed **ECDSA P-256** certificate and wrap it in a PKCS#12.
pub fn self_signed_p256_p12(password: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
    let subject = Name::from_str("CN=pdf_signer P-256,O=StrategicProjects,C=BR").unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key()).unwrap();
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap(),
        subject,
        spki,
        &signing_key,
    )
    .unwrap()
    .build::<p256::ecdsa::DerSignature>()
    .unwrap();
    let key_der = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    ec_p12(password, &key_der, &cert.to_der().unwrap())
}

/// Build a self-signed **ECDSA P-384** certificate and wrap it in a PKCS#12.
pub fn self_signed_p384_p12(password: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let subject = Name::from_str("CN=pdf_signer P-384,O=StrategicProjects,C=BR").unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key()).unwrap();
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap(),
        subject,
        spki,
        &signing_key,
    )
    .unwrap()
    .build::<p384::ecdsa::DerSignature>()
    .unwrap();
    let key_der = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    ec_p12(password, &key_der, &cert.to_der().unwrap())
}

/// Build a self-signed **Ed25519** certificate and wrap it in a PKCS#12.
pub fn self_signed_ed25519_p12(password: &str) -> Vec<u8> {
    use rsa::pkcs8::EncodePrivateKey;
    let mut rng = rand::thread_rng();
    let sk = ed25519_dalek::SigningKey::generate(&mut rng);
    let subject = Name::from_str("CN=pdf_signer Ed25519,O=StrategicProjects,C=BR").unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(sk.verifying_key()).unwrap();
    let signer = crate::crypto::Ed25519Signer(sk.clone());
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap(),
        subject,
        spki,
        &signer,
    )
    .unwrap()
    .build::<crate::crypto::Ed25519Sig>()
    .unwrap();
    let key_der = sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
    ec_p12(password, &key_der, &cert.to_der().unwrap())
}

fn ec_p12(password: &str, key_der: &[u8], cert_der: &[u8]) -> Vec<u8> {
    let chain = PrivateKeyChain::new(
        key_der,
        b"poc",
        vec![P12Certificate::from_der(cert_der).unwrap()],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    ks.writer(password).write().unwrap()
}

/// A tiny 4×4 RGBA PNG (opaque red), for testing image appearances.
pub fn tiny_png() -> Vec<u8> {
    let (w, h) = (4u32, 4u32);
    let mut pixels = Vec::with_capacity((w * h * 4) as usize);
    for _ in 0..(w * h) {
        pixels.extend_from_slice(&[220, 30, 30, 255]);
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().unwrap();
        writer.write_image_data(&pixels).unwrap();
    }
    out
}

/// A minimal one-page PDF that uses a **cross-reference stream** (PDF 1.5)
/// instead of a traditional xref table, for testing the xref-stream path.
pub fn sample_pdf_xref_stream() -> Vec<u8> {
    let content: &[u8] = b"BT /F1 24 Tf 72 720 Td (xref-stream sample) Tj ET";
    let mut out = Vec::new();
    let mut off = [0usize; 7];
    out.extend_from_slice(b"%PDF-1.5\n");
    off[1] = out.len();
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    off[2] = out.len();
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    off[3] = out.len();
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
    );
    off[4] = out.len();
    out.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    out.extend_from_slice(content);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    off[5] = out.len();
    out.extend_from_slice(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");
    off[6] = out.len();

    // Uncompressed cross-reference stream, W = [1, 4, 2], Index [0 7].
    let mut data = vec![0u8, 0, 0, 0, 0, 0xFF, 0xFF]; // object 0: free
    for &o in &off[1..=6] {
        data.push(1);
        data.extend_from_slice(&(o as u32).to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
    }
    out.extend_from_slice(
        format!(
            "6 0 obj\n<< /Type /XRef /Size 7 /Root 1 0 R /W [1 4 2] /Index [0 7] /Length {} >>\nstream\n",
            data.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    out.extend_from_slice(format!("startxref\n{}\n%%EOF\n", off[6]).as_bytes());
    out
}

/// Build a self-signed RSA-2048 certificate and wrap it in a PKCS#12 keystore.
pub fn self_signed_p12(password: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let signing_key = SigningKey::<Sha256>::new(priv_key.clone());

    let subject =
        Name::from_str("CN=pdf_signer PoC,O=StrategicProjects,C=BR").expect("subject name");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key()).expect("spki from key");

    let builder = CertificateBuilder::new(
        Profile::Root, // self-signed root: issuer == subject
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 3600)).expect("validity"),
        subject,
        spki,
        &signing_key,
    )
    .expect("certificate builder");
    let cert = builder.build::<Signature>().expect("build cert");
    let cert_der = cert.to_der().expect("cert der");

    let key_der = priv_key
        .to_pkcs8_der()
        .expect("pkcs8 der")
        .as_bytes()
        .to_vec();

    let p12_cert = P12Certificate::from_der(&cert_der).expect("p12 cert");
    let chain = PrivateKeyChain::new(&key_der, b"poc", vec![p12_cert]);

    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    ks.writer(password).write().expect("write p12")
}

/// Build a tiny PKI — a self-signed root CA and a leaf signed by it — and
/// return `(p12, root_cert_der)`. The p12 holds the leaf key + `[leaf, root]`
/// chain; `root_cert_der` is the trust anchor for chain-validation tests.
pub fn ca_signed_p12(password: &str) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).expect("validity");

    // Root CA (self-signed).
    let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root keygen");
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_name = Name::from_str("CN=PoC Test Root CA,O=StrategicProjects,C=BR").unwrap();
    let root_spki = SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap();
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        root_spki,
        &root_signing,
    )
    .expect("root builder")
    .build::<Signature>()
    .expect("build root");
    let root_der = root_cert.to_der().expect("root der");

    // Leaf, signed by the root key.
    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf keygen");
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let leaf_name = Name::from_str("CN=PoC Signer,O=StrategicProjects,C=BR").unwrap();
    let leaf_spki = SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap();
    let leaf_cert = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root_name,
            enable_key_agreement: false,
            enable_key_encipherment: true,
        },
        SerialNumber::from(2u32),
        validity,
        leaf_name,
        leaf_spki,
        &root_signing, // signed by the ROOT key
    )
    .expect("leaf builder")
    .build::<Signature>()
    .expect("build leaf");
    let leaf_der = leaf_cert.to_der().expect("leaf der");

    let key_der = leaf_key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec();
    let chain = PrivateKeyChain::new(
        &key_der,
        b"poc",
        vec![
            P12Certificate::from_der(&leaf_der).expect("p12 leaf"),
            P12Certificate::from_der(&root_der).expect("p12 root"),
        ],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    (ks.writer(password).write().expect("write p12"), root_der)
}

/// Root CA that name-constrains the leaf's exact DN — permitted (`excluded` =
/// false) or excluded (true). Returns `(p12, root_cert_der)`.
pub fn ca_name_constrained_p12(password: &str, excluded: bool) -> (Vec<u8>, Vec<u8>) {
    use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::NameConstraints;

    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();
    let root_name = Name::from_str("CN=NC Root,O=StrategicProjects,C=BR").unwrap();
    let leaf_name = Name::from_str("CN=NC Leaf,O=StrategicProjects,C=BR").unwrap();

    let subtree = GeneralSubtree {
        base: GeneralName::DirectoryName(leaf_name.clone()),
        minimum: 0,
        maximum: None,
    };
    let nc = if excluded {
        NameConstraints {
            permitted_subtrees: None,
            excluded_subtrees: Some(vec![subtree]),
        }
    } else {
        NameConstraints {
            permitted_subtrees: Some(vec![subtree]),
            excluded_subtrees: None,
        }
    };

    let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let mut root_builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap();
    root_builder.add_extension(&nc).unwrap();
    let root_cert = root_builder.build::<Signature>().unwrap();
    let root_der = root_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let leaf_cert = CertificateBuilder::new(
        leaf_profile(root_name),
        SerialNumber::from(2u32),
        validity,
        leaf_name,
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let p12 = leaf_p12(password, &leaf_key, &leaf_cert.to_der().unwrap(), &root_der);
    (p12, root_der)
}

/// Root CA + leaf where the leaf asserts `policy_oid`. Returns `(p12, root_der)`.
pub fn ca_with_policy_p12(password: &str, policy_oid: &str) -> (Vec<u8>, Vec<u8>) {
    use x509_cert::ext::pkix::certpolicy::PolicyInformation;
    use x509_cert::ext::pkix::CertificatePolicies;

    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();
    let root_name = Name::from_str("CN=Policy Root,O=StrategicProjects,C=BR").unwrap();

    let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let root_der = root_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let pols = CertificatePolicies(vec![PolicyInformation {
        policy_identifier: ObjectIdentifier::new(policy_oid).unwrap(),
        policy_qualifiers: None,
    }]);
    let mut leaf_builder = CertificateBuilder::new(
        leaf_profile(root_name),
        SerialNumber::from(2u32),
        validity,
        Name::from_str("CN=Policy Leaf,O=StrategicProjects,C=BR").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap();
    leaf_builder.add_extension(&pols).unwrap();
    let leaf_cert = leaf_builder.build::<Signature>().unwrap();
    let p12 = leaf_p12(password, &leaf_key, &leaf_cert.to_der().unwrap(), &root_der);
    (p12, root_der)
}

/// Root → intermediate (asserts `idp`, maps `idp`→`sdp`) → leaf (asserts `sdp`).
/// Exercises RFC 5280 policy mapping. Returns `(p12, root_der)`.
pub fn ca_chain_policy_mapping_p12(password: &str, idp: &str, sdp: &str) -> (Vec<u8>, Vec<u8>) {
    use x509_cert::ext::pkix::certpolicy::PolicyInformation;
    use x509_cert::ext::pkix::{CertificatePolicies, PolicyMapping, PolicyMappings};

    let idp = ObjectIdentifier::new(idp).unwrap();
    let sdp = ObjectIdentifier::new(sdp).unwrap();
    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();

    let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_name = Name::from_str("CN=PM Root,O=StrategicProjects,C=BR").unwrap();
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let root_der = root_cert.to_der().unwrap();

    let inter_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let inter_signing = SigningKey::<Sha256>::new(inter_key);
    let inter_name = Name::from_str("CN=PM Intermediate,O=StrategicProjects,C=BR").unwrap();
    let mut inter_builder = CertificateBuilder::new(
        Profile::SubCA {
            issuer: root_name,
            path_len_constraint: Some(0),
        },
        SerialNumber::from(2u32),
        validity,
        inter_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(inter_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap();
    inter_builder
        .add_extension(&CertificatePolicies(vec![PolicyInformation {
            policy_identifier: idp,
            policy_qualifiers: None,
        }]))
        .unwrap();
    inter_builder
        .add_extension(&PolicyMappings(vec![PolicyMapping {
            issuer_domain_policy: idp,
            subject_domain_policy: sdp,
        }]))
        .unwrap();
    let inter_cert = inter_builder.build::<Signature>().unwrap();
    let inter_der = inter_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let mut leaf_builder = CertificateBuilder::new(
        leaf_profile(inter_name),
        SerialNumber::from(3u32),
        validity,
        Name::from_str("CN=PM Leaf,O=StrategicProjects,C=BR").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &inter_signing,
    )
    .unwrap();
    leaf_builder
        .add_extension(&CertificatePolicies(vec![PolicyInformation {
            policy_identifier: sdp,
            policy_qualifiers: None,
        }]))
        .unwrap();
    let leaf_cert = leaf_builder.build::<Signature>().unwrap();

    let key_der = leaf_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let chain = PrivateKeyChain::new(
        &key_der,
        b"poc",
        vec![
            P12Certificate::from_der(&leaf_cert.to_der().unwrap()).unwrap(),
            P12Certificate::from_der(&inter_der).unwrap(),
            P12Certificate::from_der(&root_der).unwrap(),
        ],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    (ks.writer(password).write().unwrap(), root_der)
}

fn leaf_profile(issuer: Name) -> Profile {
    Profile::Leaf {
        issuer,
        enable_key_agreement: false,
        enable_key_encipherment: true,
    }
}

fn leaf_p12(password: &str, leaf_key: &RsaPrivateKey, leaf_der: &[u8], root_der: &[u8]) -> Vec<u8> {
    let key_der = leaf_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let chain = PrivateKeyChain::new(
        &key_der,
        b"poc",
        vec![
            P12Certificate::from_der(leaf_der).unwrap(),
            P12Certificate::from_der(root_der).unwrap(),
        ],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    ks.writer(password).write().unwrap()
}

/// Build a three-level PKI (root CA → intermediate CA → leaf). Returns
/// `(p12, root_cert_der)`; the p12 holds the leaf key + `[leaf, intermediate,
/// root]` chain, exercising path building through an intermediate.
pub fn ca_chain3_p12(password: &str) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).expect("validity");

    let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_name = Name::from_str("CN=PoC Root CA,O=StrategicProjects,C=BR").unwrap();
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .expect("root builder")
    .build::<Signature>()
    .expect("root");
    let root_der = root_cert.to_der().unwrap();

    let inter_key = RsaPrivateKey::new(&mut rng, 2048).expect("inter key");
    let inter_signing = SigningKey::<Sha256>::new(inter_key);
    let inter_name = Name::from_str("CN=PoC Intermediate CA,O=StrategicProjects,C=BR").unwrap();
    let inter_cert = CertificateBuilder::new(
        Profile::SubCA {
            issuer: root_name,
            path_len_constraint: Some(0),
        },
        SerialNumber::from(2u32),
        validity,
        inter_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(inter_signing.verifying_key()).unwrap(),
        &root_signing, // signed by root
    )
    .expect("inter builder")
    .build::<Signature>()
    .expect("inter");
    let inter_der = inter_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf key");
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let leaf_name = Name::from_str("CN=PoC Signer,O=StrategicProjects,C=BR").unwrap();
    let leaf_cert = CertificateBuilder::new(
        Profile::Leaf {
            issuer: inter_name,
            enable_key_agreement: false,
            enable_key_encipherment: true,
        },
        SerialNumber::from(3u32),
        validity,
        leaf_name,
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &inter_signing, // signed by intermediate
    )
    .expect("leaf builder")
    .build::<Signature>()
    .expect("leaf");
    let leaf_der = leaf_cert.to_der().unwrap();

    let key_der = leaf_key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec();
    let chain = PrivateKeyChain::new(
        &key_der,
        b"poc",
        vec![
            P12Certificate::from_der(&leaf_der).unwrap(),
            P12Certificate::from_der(&inter_der).unwrap(),
            P12Certificate::from_der(&root_der).unwrap(),
        ],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    (ks.writer(password).write().expect("write p12"), root_der)
}
