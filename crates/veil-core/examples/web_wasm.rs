//! Web client WASM module (`docs/HUB.md` §13.39, §13.40): diffing, snapshot
//! signature verification, sealed-entry classification, and passkey-PRF sealing
//! of a freshly generated browser device identity inside a Worker — with **no
//! secret decryption or key ring unwrap path**.

use std::sync::Mutex;

use veil_core::{
    clock,
    hub::web::{
        classify_file_meta, diff_text_bounded, inspect_object_no_secrets, seal_new_browser_device, WebFileState, WebObjectSummary,
    },
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

/// Self-check when invoked natively (`cargo run --example web_wasm ...`).
pub fn self_check() -> Result<String, String> {
    let diff = diff_text_bounded("fn a() -> u32 { 1 }\n", "fn a() -> u32 { 2 }\n", 65_536);
    if diff.binary || diff.too_large || diff.hunks.len() != 1 {
        return Err("unexpected diff output".into());
    }
    let state = classify_file_meta(r#"{"sealed":true,"encoding":"object","kind":"file"}"#).map_err(|e| e.to_string())?;
    if state != WebFileState::Sealed {
        return Err("sealed metadata was not classified as Sealed".into());
    }
    let forged = classify_file_meta(r#"{"sealed":false,"encoding":"object","kind":"file"}"#).map_err(|e| e.to_string())?;
    if forged != WebFileState::Sealed {
        return Err("non-content object encoding was not classified as Sealed".into());
    }
    let sealed_raw = b"veil:seal\nnot-opened-by-browser";
    let inspected = inspect_object_no_secrets(sealed_raw).map_err(|e| e.to_string())?;
    if inspected != WebObjectSummary::Sealed {
        return Err("sealed raw object was not classified as Sealed".into());
    }
    let bundle = seal_new_browser_device("alice", "cred-self-check", &[0x42; 32]).map_err(|e| e.to_string())?;
    if !bundle.public_identity.starts_with("veil1") || bundle.fingerprint.len() != 24 {
        return Err("invalid sealed browser device bundle".into());
    }
    Ok("web_wasm: self-check ok (no secret decryption paths)\n".into())
}

/// Allocate `len` bytes in WASM linear memory for JS callers.
#[unsafe(no_mangle)]
pub extern "C" fn veil_web_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free a buffer previously allocated with `veil_web_alloc`.
///
/// # Safety
/// `ptr` and `cap` must come from a matching `veil_web_alloc(cap)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_web_free(ptr: *mut u8, cap: usize) {
    if !ptr.is_null() && cap > 0 {
        unsafe {
            drop(Vec::from_raw_parts(ptr, 0, cap));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn veil_web_out_ptr() -> *const u8 {
    OUT.lock().unwrap().as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn veil_web_out_len() -> usize {
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

/// Compute bounded unified diff hunks in WASM.
///
/// # Safety
/// Input pointers must be valid for their given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_web_diff(old_ptr: *const u8, old_len: usize, new_ptr: *const u8, new_len: usize, max_bytes: usize) -> i32 {
    install_clock();
    let res = (|| {
        let old = unsafe { utf8(old_ptr, old_len) }?;
        let new = unsafe { utf8(new_ptr, new_len) }?;
        Ok(diff_text_bounded(old, new, max_bytes))
    })();
    write_out(res)
}

/// Classify file metadata in WASM (`sealed` or `encoding != "content"` -> `"sealed"`).
///
/// # Safety
/// `ptr` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_web_classify_file(ptr: *const u8, len: usize) -> i32 {
    let res = (|| {
        let meta = unsafe { utf8(ptr, len) }?;
        classify_file_meta(meta)
    })();
    write_out(res)
}

/// Inspect a raw Veil object in WASM (verifying snapshot signatures, refusing
/// to open sealed secrets).
///
/// # Safety
/// `ptr` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_web_inspect_object(ptr: *const u8, len: usize) -> i32 {
    install_clock();
    let raw = unsafe { slice(ptr, len) };
    write_out(inspect_object_no_secrets(raw))
}

/// Generate a fresh browser device identity inside WASM memory and seal its
/// private keys under a 32-byte WebAuthn PRF output (`HUB_WEB_PRF_KEY`),
/// returning only public keys, fingerprint, and ciphertext for IndexedDB.
///
/// # Safety
/// Input pointers must be valid for their given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_web_seal_new_device(
    person_ptr: *const u8,
    person_len: usize,
    cred_ptr: *const u8,
    cred_len: usize,
    prf_ptr: *const u8,
    prf_len: usize,
) -> i32 {
    install_clock();
    let res = (|| {
        let person = unsafe { utf8(person_ptr, person_len) }?;
        let cred = unsafe { utf8(cred_ptr, cred_len) }?;
        let prf = unsafe { slice(prf_ptr, prf_len) };
        seal_new_browser_device(person, cred, prf)
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
    match self_check() {
        Ok(msg) => print!("{msg}"),
        Err(e) => {
            eprintln!("web_wasm: {e}");
            std::process::exit(1);
        }
    }
}
