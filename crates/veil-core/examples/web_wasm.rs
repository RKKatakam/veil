//! Web client WASM module (`docs/HUB.md` §13.39): diffing, snapshot
//! signature verification, sealed-entry classification, and device-signed
//! login / PR review in browser memory, with **no secret decryption path**.

use std::sync::Mutex;

use veil_core::{
    clock,
    hub::web::{
        classify_file_meta, diff_text_bounded, inspect_object_no_secrets, sign_web_login, sign_web_pr_review, WebFileState, WebObjectSummary,
    },
    Identity,
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
    let alice = Identity::generate("alice");
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
    let login = sign_web_login(&alice.to_json(), "localhost:4443", &"22".repeat(32), Some("alice")).map_err(|e| e.to_string())?;
    if login.key != alice.verifying_hex() {
        return Err("login key mismatch".into());
    }
    let sig = sign_web_pr_review(&alice.to_json(), "acme", "pr-abcdef12", "patch-1", "approve").map_err(|e| e.to_string())?;
    if sig.len() != 128 {
        return Err("review signature length mismatch".into());
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

/// Generate a fresh in-memory browser identity JSON (for tests / ephemeral signing).
///
/// # Safety
/// `name_ptr` must be valid for `name_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_web_generate_identity(name_ptr: *const u8, name_len: usize) -> i32 {
    install_clock();
    let res = (|| {
        let name = unsafe { utf8(name_ptr, name_len) }?;
        Ok(Identity::generate(name).to_json())
    })();
    write_out(res)
}

/// Sign a single-use login challenge (`hub-login`) in WASM memory.
///
/// # Safety
/// Input pointers must be valid for their given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_web_sign_login(
    id_ptr: *const u8,
    id_len: usize,
    hub_ptr: *const u8,
    hub_len: usize,
    chal_ptr: *const u8,
    chal_len: usize,
) -> i32 {
    install_clock();
    let res = (|| {
        let id = unsafe { utf8(id_ptr, id_len) }?;
        let hub = unsafe { utf8(hub_ptr, hub_len) }?;
        let chal = unsafe { utf8(chal_ptr, chal_len) }?;
        sign_web_login(id, hub, chal, None)
    })();
    write_out(res)
}

/// Sign a PR review verdict (`hub-pr-review`) in WASM memory.
///
/// # Safety
/// Input pointers must be valid for their given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_web_sign_review(
    id_ptr: *const u8,
    id_len: usize,
    proj_ptr: *const u8,
    proj_len: usize,
    pr_ptr: *const u8,
    pr_len: usize,
    patch_ptr: *const u8,
    patch_len: usize,
    verdict_ptr: *const u8,
    verdict_len: usize,
) -> i32 {
    install_clock();
    let res = (|| {
        let id = unsafe { utf8(id_ptr, id_len) }?;
        let proj = unsafe { utf8(proj_ptr, proj_len) }?;
        let pr = unsafe { utf8(pr_ptr, pr_len) }?;
        let patch = unsafe { utf8(patch_ptr, patch_len) }?;
        let verdict = unsafe { utf8(verdict_ptr, verdict_len) }?;
        sign_web_pr_review(id, proj, pr, patch, verdict)
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
