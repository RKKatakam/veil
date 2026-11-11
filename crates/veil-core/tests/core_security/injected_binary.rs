//! BUG-099: binary isolated files (PKCS#12 bundles, Java keystores, DER
//! keys) injected into a `ws exec --with-isolated` sandbox are recognised
//! when a command copies them, whole, in part, or re-encoded.
//!
//! Real keystores are generated with `openssl` when it is installed;
//! otherwise (and in addition) a synthetic DER key is used.

use std::{path::Path, process::Command};

use veil_core::builder::{InjectedSecrets, INJECTED_RULE};

/// A synthetic DER `RSAPrivateKey`: ASN.1 structure around random integers.
fn synthetic_der(seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rnd = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    };
    let int = |body: Vec<u8>| {
        let mut v = vec![0x02, 0x82, (body.len() >> 8) as u8, body.len() as u8];
        v.extend(body);
        v
    };
    let mut seq = vec![0x02, 0x01, 0x00];
    for n in [257, 3, 256, 129, 129, 128, 128, 128] {
        seq.extend(int(rnd(n)));
    }
    let mut out = vec![0x30, 0x82, (seq.len() >> 8) as u8, seq.len() as u8];
    out.extend(seq);
    out
}

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `(name, bytes)` of real binary keystores: a PKCS#12 bundle and a DER
/// PKCS#8 key, plus the PEM key they were made from. `None` without openssl.
fn real_keystores(dir: &Path, tag: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let key = format!("{tag}.key.pem");
    let crt = format!("{tag}.crt.pem");
    let p12 = format!("{tag}.p12");
    let der = format!("{tag}.key.der");
    let subj = format!("/CN={tag}.example");
    let ok = openssl(dir, &["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", &key, "-out", &crt, "-subj", &subj, "-days", "1"])
        && openssl(dir, &["pkcs12", "-export", "-inkey", &key, "-in", &crt, "-out", &p12, "-passout", "pass:changeit"])
        && openssl(dir, &["pkey", "-in", &key, "-outform", "DER", "-out", &der]);
    if !ok {
        eprintln!("openssl not available: real keystores skipped");
        return None;
    }
    let read = |n: &str| std::fs::read(dir.join(n)).unwrap();
    Some((read(&p12), read(&der), read(&key)))
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            out.push(if k <= c.len() { A[(n >> (18 - 6 * k) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn wrap(s: &str, width: usize) -> String {
    s.as_bytes().chunks(width).map(|l| format!("{}\n", std::str::from_utf8(l).unwrap())).collect()
}

/// Every way a command could carry `secret` out of the sandbox.
fn copies(secret: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mid = secret.len() / 2;
    let mut bundle = b"\x7fELF\x02\x01\x01 some binary header".to_vec();
    bundle.extend(secret);
    bundle.extend(b"trailer");
    vec![
        ("verbatim copy", secret.to_vec()),
        ("embedded in a bundle", bundle),
        ("a 64-byte slice", secret[mid..mid + 64].to_vec()),
        ("base64, one line", b64(secret).into_bytes()),
        ("base64 wrapped at 76 (`base64`)", wrap(&b64(secret), 76).into_bytes()),
        (
            "PEM-wrapped",
            format!("-----BEGIN PRIVATE KEY-----\n{}-----END PRIVATE KEY-----\n", wrap(&b64(secret), 64)).into_bytes(),
        ),
        ("base64 of a tail (other alignment)", b64(&secret[mid + 1..]).into_bytes()),
        ("hex (`xxd -p`)", wrap(&hex::encode(secret), 60).into_bytes()),
        ("HEX upper case", hex::encode_upper(secret).into_bytes()),
        ("hex of a slice", hex::encode(&secret[mid..mid + 40]).into_bytes()),
    ]
}

fn assert_all_caught(inj: &InjectedSecrets, secret: &[u8], what: &str) {
    assert!(!inj.is_empty(), "{what}: no needle derived");
    for (how, data) in copies(secret) {
        let f = inj.find(&data).unwrap_or_else(|| panic!("{what}: {how} not recognised"));
        assert_eq!(f.rule, INJECTED_RULE);
        assert!(!f.excerpt.is_empty());
    }
}

#[test]
fn a_synthetic_der_key_is_recognised_in_every_copy() {
    let der = synthetic_der(1);
    let inj = InjectedSecrets::from_files([("deploy.der", &der[..])]);
    assert_all_caught(&inj, &der, "synthetic DER");
    // Another key of the same shape (same ASN.1 headers) is not a copy.
    let other = synthetic_der(2);
    assert!(inj.find(&other).is_none(), "an unrelated key of the same kind matched");
    assert!(inj.find(&vec![0u8; 4096]).is_none(), "zero padding matched");
}

#[test]
fn real_keystores_are_recognised_in_every_copy_and_unrelated_ones_are_not() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((p12, der, pem)) = real_keystores(tmp.path(), "a") else { return };
    let inj = InjectedSecrets::from_files([("server.p12", &p12[..]), ("key.der", &der[..])]);
    assert_all_caught(&inj, &p12, "PKCS#12");
    assert_all_caught(&inj, &der, "DER PKCS#8 key");

    // An injected PEM key converted to DER by the command is caught too.
    let inj_pem = InjectedSecrets::from_files([("id.pem", &pem[..])]);
    assert!(inj_pem.find(&der).is_some(), "PEM key converted to DER");

    // Keystores and certificates made independently share their ASN.1
    // structure (OIDs, RSA headers) but no key material: never a match.
    let Some((p12_b, der_b, pem_b)) = real_keystores(tmp.path(), "b") else { return };
    let crt_b = std::fs::read(tmp.path().join("b.crt.pem")).unwrap();
    for (what, data) in [("p12", &p12_b), ("der", &der_b), ("pem", &pem_b), ("cert", &crt_b)] {
        assert!(inj.find(data).is_none(), "an unrelated {what} matched");
        assert!(inj_pem.find(data).is_none(), "an unrelated {what} matched the PEM key");
    }
}

#[test]
fn needles_are_bounded_for_large_binary_files() {
    // 8 MiB of pseudo-random bytes: building and matching stay fast, and
    // a slice of it is still found.
    let big: Vec<u8> = {
        let mut x = 0x1234_5678_9abc_def1u64;
        (0..8 << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    };
    let t = std::time::Instant::now();
    let inj = InjectedSecrets::from_files([("blob.jks", &big[..])]);
    let unrelated = vec![0x5au8; 16 << 20];
    assert!(inj.find(&unrelated).is_none());
    // A slice long enough to span two strides at the large file's stride.
    let stride = (big.len().div_ceil(8192)).next_multiple_of(2);
    let at = 3 << 20;
    assert!(inj.find(&big[at..at + 2 * stride + 64]).is_some());
    assert!(t.elapsed() < std::time::Duration::from_secs(30), "took {:?}", t.elapsed());
}

/// BUG-1931: `find_new` lets through a value the recorded version of the
/// same path already held, and nothing else, value by value: another value
/// of the secret in the same file is still found, and so is everything in
/// a file whose recorded version held nothing (`find`'s answer).
#[test]
fn bug_1931_find_new_lets_through_only_what_the_recorded_version_held() {
    const URL: &str = "http://localhost:3000/app";
    const KEY: &str = "Xk29vLq8sPzQw7LmTr4Bn6Yc";
    const OTHER: &str = "Qm83nRt5wZx1cVb7yHj2kLp9";
    let env = format!("APP_URL={URL}\nAPI_KEY={KEY}\nOTHER_KEY={OTHER}\n");
    let inj = InjectedSecrets::from_files([(".env", env.as_bytes())]);
    let readme = format!("Run at {URL}.\n");
    let edited = format!("Run at {URL}.\nMore docs.\n");
    assert!(inj.find(edited.as_bytes()).is_some(), "control: the whole-file search finds the URL");
    assert!(inj.find_new(None, edited.as_bytes(), readme.as_bytes()).is_none(), "the URL was there before");
    assert!(inj.find_new(None, edited.as_bytes(), b"").is_some(), "the URL is new to a file that held nothing");
    assert!(inj.find_new(None, edited.as_bytes(), b"Run it.\n").is_some(), "the URL is new to a file that did not hold it");
    // Another value of the sealed file is still the command's copy.
    let f = inj.find_new(None, format!("Run at {URL}.\nkey {KEY}\n").as_bytes(), readme.as_bytes()).expect("the key is new");
    assert_eq!((f.rule, f.line), (INJECTED_RULE, 2));
    assert!(inj.find_new(None, env.as_bytes(), readme.as_bytes()).is_some(), "a whole copy of the sealed file");
    // A file that held one secret value is not free to take another.
    let leaked = format!("old {KEY}\n");
    assert!(inj.find_new(None, format!("old {KEY}\nedited\n").as_bytes(), leaked.as_bytes()).is_none());
    assert!(inj.find_new(None, format!("old {KEY}\nnew {OTHER}\n").as_bytes(), leaked.as_bytes()).is_some());

    // Binary secrets (windows): a part the recorded version held, and
    // another part.
    let der = synthetic_der(1);
    let inj = InjectedSecrets::from_files([("deploy.der", &der[..])]);
    let mid = der.len() / 2;
    let (held, fresh) = (hex::encode(&der[mid..mid + 40]), hex::encode(&der[mid + 200..mid + 240]));
    let before = format!("fingerprint {held}\n");
    assert!(inj.find(before.as_bytes()).is_some(), "control: a slice of the key is found");
    assert!(inj.find_new(None, format!("fingerprint {held}\nnote\n").as_bytes(), before.as_bytes()).is_none(), "the slice was there before");
    assert!(inj.find_new(None, format!("fingerprint {held}\n{fresh}\n").as_bytes(), before.as_bytes()).is_some(), "another slice is new");
    assert!(inj.find_new(None, &der, before.as_bytes()).is_some(), "the whole key is new");
}
