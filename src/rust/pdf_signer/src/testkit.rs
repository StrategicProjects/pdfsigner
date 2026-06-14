//! Test/demo helpers: build a minimal sample PDF and a self-signed PKCS#12.
//!
//! These exist so the PoC is fully reproducible without external fixtures and
//! without OpenSSL — everything is pure RustCrypto. They are not part of the
//! production signing/verification surface.

use std::str::FromStr;
use std::time::Duration;

use lopdf::content::{Content, Operation};
use lopdf::{dictionary, Document, Object, Stream};

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
