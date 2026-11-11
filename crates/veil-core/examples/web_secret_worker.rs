//! Dedicated Web Worker WASM module for S26 browser secrets (`docs/HUB.md`
//! §13.40; `docs/design/server/phase-4-agent-scale.md` §4.12).
//!
//! Served **only** on `/p/{p}/web/secret-worker.wasm` when a project admin has
//! enabled `web_secrets`. Unseals the passkey-PRF-protected browser device
//! identity inside WASM linear memory, verifies signed key rings and project
//! fingerprints, checks content-addressed `ObjectId`s, and opens `Object::Sealed`
//! secret files strictly on demand.

use std::sync::Mutex;

use veil_core::{
    clock,
    hub::web_secrets::{open_secret_in_worker, verify_sealed_browser_device},
};

static OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn write_out<T: serde::Serialize>(val: Result<T, veil_core::VeilError>) -> i32 {
    match val.and_then(|v| serde_json::to_vec(&v).map_err(Into::into)) {
        Ok(bytes) => {
            *OUT.lock().unwrap() = bytes;
            0
        }
        Err(e) => {
            *OUT.lock().unwrap() = e.to_string().into_bytes();
            1
        }
    }
}

fn install_clock() {
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    {
        #[link(wasm_import_module = "env")]
        unsafe extern "C" {
            fn veil_now_ms() -> f64;
        }
        clock::set_clock(std::sync::Arc::new(|| unsafe { veil_now_ms() } as i64));
    }
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    {
        use veil_core::clock::Clock as _;
        clock::set_clock(std::sync::Arc::new(|| clock::SystemClock.now_millis().max(1_700_000_000_000)));
    }
}

#[derive(serde::Serialize)]
struct Fixture {
    credential_id: String,
    prf_hex: String,
    sealed_identity_hex: String,
    project_fp: String,
    rings_json: String,
    object_id: String,
    object_hex: String,
    rotated_object_id: String,
    rotated_object_hex: String,
    expected_plaintext: String,
}

fn build_fixture() -> Result<Fixture, String> {
    use std::sync::Arc;
    use veil_core::{
        crypto::Envelope,
        hub::web::seal_new_browser_device,
        identity::parse_public_identity,
        keychain::{project_fingerprint, Keychain},
        object::Object,
        vfs::MemoryBackend,
        Identity, ObjectId,
    };

    let prf = [0x7bu8; 32];
    let cred_id = "cred-worker-fixture-1";
    let bundle = seal_new_browser_device("alice", cred_id, &prf).map_err(|e| e.to_string())?;
    let _browser_pub = parse_public_identity(&bundle.public_identity).map_err(|e| e.to_string())?;

    let admin = Identity::generate("alice");
    let backend = Arc::new(MemoryBackend::new());
    let kc = Keychain::new(backend, Some(admin), "repo-worker-fixture".into());
    kc.set_format(8);
    kc.create_scope("team").map_err(|e| e.to_string())?;
    let ring0 = kc.load_ring("team").map_err(|e| e.to_string())?.ok_or("missing team ring")?;
    let st0 = ring0.verify()?;
    let proj_id = st0.project.ok_or_else(|| "missing project id on genesis".to_string())?;
    let project_fp = project_fingerprint(&proj_id);

    kc.grant("team", &bundle.public_identity, "alice").map_err(|e| e.to_string())?;
    let (label, key) = kc.sealing_key("team").map_err(|e| e.to_string())?;
    let expected_plaintext = "DATABASE_URL=postgres://worker-secret-canary\n".to_string();
    let env = Envelope::seal_deterministic(&key, &label, expected_plaintext.as_bytes()).map_err(|e| e.to_string())?;
    let raw_obj = Object::Sealed(env).encode();
    let object_id = ObjectId::hash(&raw_obj).hex();

    let ring_granted = kc.load_ring("team").map_err(|e| e.to_string())?.ok_or("missing team ring")?;
    let mut rings_map = std::collections::BTreeMap::new();
    rings_map.insert("team".to_string(), serde_json::to_string(&ring_granted).map_err(|e| e.to_string())?);
    let rings_json = serde_json::to_string(&rings_map).map_err(|e| e.to_string())?;

    // Revoke browser device -> rotates to generation 1; browser device must NOT open new secrets!
    kc.revoke("team", &bundle.public_identity).map_err(|e| e.to_string())?;
    let (rot_label, rot_key) = kc.sealing_key("team").map_err(|e| e.to_string())?;
    let rot_env = Envelope::seal_deterministic(&rot_key, &rot_label, b"POST_REVOKE_SECRET\n").map_err(|e| e.to_string())?;
    let rot_raw = Object::Sealed(rot_env).encode();
    let rotated_object_id = ObjectId::hash(&rot_raw).hex();

    Ok(Fixture {
        credential_id: cred_id.into(),
        prf_hex: hex::encode(prf),
        sealed_identity_hex: bundle.sealed_identity_hex,
        project_fp,
        rings_json,
        object_id,
        object_hex: hex::encode(raw_obj),
        rotated_object_id,
        rotated_object_hex: hex::encode(rot_raw),
        expected_plaintext,
    })
}

pub fn self_check() -> Result<String, String> {
    let fx = build_fixture()?;
    let prf = hex::decode(&fx.prf_hex).map_err(|e| e.to_string())?;
    let raw = hex::decode(&fx.object_hex).map_err(|e| e.to_string())?;
    let pub_dev = verify_sealed_browser_device(&fx.credential_id, &prf, &fx.sealed_identity_hex).map_err(|e| e.to_string())?;
    if !pub_dev.public_identity.starts_with("veil1") {
        return Err("unexpected public identity prefix".into());
    }
    let opened = open_secret_in_worker(
        &fx.credential_id,
        &prf,
        &fx.sealed_identity_hex,
        &fx.rings_json,
        Some(&fx.project_fp),
        Some(&fx.object_id),
        &raw,
    )
    .map_err(|e| e.to_string())?;
    if opened.text.as_deref() != Some(fx.expected_plaintext.as_str()) {
        return Err("decrypted plaintext mismatch".into());
    }
    let rot_raw = hex::decode(&fx.rotated_object_hex).map_err(|e| e.to_string())?;
    if open_secret_in_worker(
        &fx.credential_id,
        &prf,
        &fx.sealed_identity_hex,
        &fx.rings_json,
        Some(&fx.project_fp),
        Some(&fx.rotated_object_id),
        &rot_raw,
    )
    .is_ok()
    {
        return Err("revoked browser device opened a post-revocation secret".into());
    }
    Ok("web_secret_worker: self-check ok\n".into())
}

#[unsafe(no_mangle)]
pub extern "C" fn veil_worker_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free a buffer previously allocated with `veil_worker_alloc`.
///
/// # Safety
/// `ptr` and `cap` must come from a matching `veil_worker_alloc(cap)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_worker_free(ptr: *mut u8, cap: usize) {
    if !ptr.is_null() && cap > 0 {
        unsafe {
            drop(Vec::from_raw_parts(ptr, 0, cap));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn veil_worker_out_ptr() -> *const u8 {
    OUT.lock().unwrap().as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn veil_worker_out_len() -> usize {
    OUT.lock().unwrap().len()
}

unsafe fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

unsafe fn utf8<'a>(ptr: *const u8, len: usize) -> Result<&'a str, veil_core::VeilError> {
    std::str::from_utf8(unsafe { slice(ptr, len) }).map_err(|e| veil_core::VeilError::Corrupt("utf8".into(), e.to_string()))
}

/// Verify a passkey-PRF-sealed browser device identity inside Worker WASM memory.
///
/// # Safety
/// Input pointers must be valid for their given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_worker_verify_device(
    cred_ptr: *const u8,
    cred_len: usize,
    prf_ptr: *const u8,
    prf_len: usize,
    sealed_ptr: *const u8,
    sealed_len: usize,
) -> i32 {
    install_clock();
    let res = (|| {
        let cred = unsafe { utf8(cred_ptr, cred_len) }?;
        let prf = unsafe { slice(prf_ptr, prf_len) };
        let sealed = unsafe { utf8(sealed_ptr, sealed_len) }?;
        verify_sealed_browser_device(cred, prf, sealed)
    })();
    write_out(res)
}

/// Open one sealed secret object inside Worker WASM memory.
///
/// # Safety
/// Input pointers must be valid for their given lengths.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_worker_open_secret(
    cred_ptr: *const u8,
    cred_len: usize,
    prf_ptr: *const u8,
    prf_len: usize,
    sealed_ptr: *const u8,
    sealed_len: usize,
    rings_ptr: *const u8,
    rings_len: usize,
    proj_fp_ptr: *const u8,
    proj_fp_len: usize,
    oid_ptr: *const u8,
    oid_len: usize,
    obj_ptr: *const u8,
    obj_len: usize,
) -> i32 {
    install_clock();
    let res = (|| {
        let cred = unsafe { utf8(cred_ptr, cred_len) }?;
        let prf = unsafe { slice(prf_ptr, prf_len) };
        let sealed = unsafe { utf8(sealed_ptr, sealed_len) }?;
        let rings = unsafe { utf8(rings_ptr, rings_len) }?;
        let proj_fp = unsafe { utf8(proj_fp_ptr, proj_fp_len) }?;
        let oid = unsafe { utf8(oid_ptr, oid_len) }?;
        let obj = unsafe { slice(obj_ptr, obj_len) };
        open_secret_in_worker(
            cred,
            prf,
            sealed,
            rings,
            (!proj_fp.is_empty()).then_some(proj_fp),
            (!oid.is_empty()).then_some(oid),
            obj,
        )
    })();
    write_out(res)
}

#[cfg(all(target_family = "wasm", target_os = "unknown", getrandom_backend = "custom"))]
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    #[link(wasm_import_module = "env")]
    unsafe extern "C" {
        fn veil_random_fill(ptr: *mut u8, len: usize) -> i32;
    }
    match unsafe { veil_random_fill(dest, len) } {
        0 => Ok(()),
        _ => Err(getrandom::Error::UNSUPPORTED),
    }
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), allow(dead_code))]
fn main() {
    install_clock();
    if std::env::args().any(|a| a == "--fixture") {
        match build_fixture().and_then(|fx| serde_json::to_string(&fx).map_err(|e| e.to_string())) {
            Ok(json) => {
                println!("{json}");
                return;
            }
            Err(e) => {
                eprintln!("web_secret_worker: {e}");
                std::process::exit(1);
            }
        }
    }
    match self_check() {
        Ok(msg) => print!("{msg}"),
        Err(e) => {
            eprintln!("web_secret_worker: {e}");
            std::process::exit(1);
        }
    }
}
