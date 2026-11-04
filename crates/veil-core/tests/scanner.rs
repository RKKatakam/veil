//! Secret scanner: false-positive guards on ordinary content, detection
//! guards, and a throughput benchmark (ignored by default):
//!
//! ```sh
//! cargo test --release -p veil-core --test scanner -- --ignored --nocapture
//! ```

use std::time::Instant;

use veil_core::secrets::scan;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn hexs(r: &mut Rng, n: usize) -> String {
    r.bytes(n).iter().map(|b| format!("{b:02x}")).collect()
}

// ---- ordinary content that must never be flagged -------------------------------------

const RUST: &str = r#"
use std::collections::HashMap;

/// Checks a user's password against the stored hash.
pub fn verify_password(user: &User, password: &str) -> Result<bool, AuthError> {
    let password_hash = user.password_hash.as_deref().ok_or(AuthError::NoPassword)?;
    let api_key = std::env::var("API_KEY").map_err(|_| AuthError::MissingKey)?;
    let secret_key = config.secret_key.clone();
    let access_token = request.headers().get("authorization").and_then(parse_bearer);
    let client_secret = settings.oauth.client_secret_v2.as_str();
    let auth_token = AuthToken::new(&api_key, Duration::from_secs(3600));
    tracing::debug!(password_len = password.len(), "verifying");
    argon2::verify_encoded(password_hash, password.as_bytes()).map_err(Into::into)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConfig {
    pub host: String,
    pub password: Option<String>,
    #[serde(rename = "apiKey")]
    pub api_key: String,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self { host: "localhost".into(), password: None, api_key: String::new() }
    }
}
"#;

const PYTHON: &str = r#"
import os
from django.conf import settings

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "")
API_KEY = settings.EXTERNAL_API_KEY
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]

def login(request, password=None, api_key=None, access_token=None):
    password = request.POST.get("password")
    access_token = oauth_client.fetch_access_token(code=request.GET["code"])
    secret_key = get_secret_key_from_vault(path="kv/app")
    client = Client(api_key=api_key, password=password, auth_token=access_token)
    user = authenticate(username=request.POST["user"], password=password)
    passwd = getpass.getpass("Password: ")
    return client.login(password_hash=hash_password(password, salt=os.urandom(16)))
"#;

const CONFIG: &str = r#"
# Application settings. Secrets come from the environment.
database:
  host: db.internal
  port: 5432
  password: ${DATABASE_PASSWORD}
  password_file: /run/secrets/db_password
redis:
  password: *default_redis_password
  auth_token: "{{ .Values.redis.authToken }}"
smtp:
  password: <your-smtp-password-here>
  api_key: changeme
oauth:
  client_secret: $OAUTH_CLIENT_SECRET
  access_token_url: https://auth.example.com/oauth/token
  private_key_path: /etc/app/keys/private_key_v2.pem
DB_PASSWORD=
API_KEY=your-api-key-goes-here
SECRET_KEY=${SECRET_KEY:-development-only}
export AUTH_TOKEN="$(cat /run/secrets/token)"
password: process.env.DB_PASSWORD_PRIMARY
api_key: os.environ.API_KEY_V2
access_token: request.session.access_token_v2
"#;

const PROSE: &str = "\
## Configuring authentication\n\n\
Set the `API_KEY` environment variable to your API key, and the `password` field \n\
to the database password. Never commit a password; use `vl secret set` instead. \n\
The access token expires after one hour, and the client secret can be rotated in \n\
the dashboard under Settings → API keys. Private keys are stored as PEM files.\n\n";

fn package_lock(r: &mut Rng) -> String {
    let name = ["left-pad", "lodash", "react-dom", "@types/node", "esbuild", "postcss"][r.below(6)];
    format!(
        "    \"node_modules/{name}\": {{\n      \"version\": \"{}.{}.{}\",\n      \"resolved\": \"https://registry.npmjs.org/{name}/-/{name}-4.17.21.tgz\",\n      \"integrity\": \"sha512-{}\",\n      \"dev\": true\n    }},\n",
        r.below(20),
        r.below(20),
        r.below(20),
        base64(&r.bytes(64))
    )
}

fn cargo_lock(r: &mut Rng) -> String {
    let name = ["serde", "tokio", "regex-automata", "aho-corasick", "sk-hash", "akia-parser"][r.below(6)];
    format!(
        "[[package]]\nname = \"{name}\"\nversion = \"1.{}.{}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n\n",
        r.below(50),
        r.below(50),
        hexs(r, 32)
    )
}

fn yarn_lock(r: &mut Rng) -> String {
    format!(
        "\"@babel/core@^7.{}.0\":\n  version \"7.{}.3\"\n  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.24.3.tgz#{}\"\n  integrity sha1-{}\n\n",
        r.below(30),
        r.below(30),
        hexs(r, 20),
        base64(&r.bytes(20))
    )
}

fn minified_js(r: &mut Rng) -> String {
    let mut s = String::new();
    for _ in 0..40 {
        let v = (b'a' + r.below(26) as u8) as char;
        s.push_str(&format!(
            "function {v}(e,t){{var n=e.password,r=t.apiKey||e.api_key;return{{password:n,apiKey:r,accessToken:this.accessToken,secret_key:void 0,authToken:e.headers[\"x-auth-token\"],h:\"{}\"}}}};",
            hexs(r, 16)
        ));
        s.push_str("var o=window.localStorage.getItem(\"access_token\"),i=Object.assign({},a,{password:function(e){return e.trim()}});");
    }
    s.push('\n');
    s
}

fn image_data_uri(r: &mut Rng) -> String {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(r.bytes(3000));
    format!(".logo{{background:url(data:image/png;base64,{})}}\n", base64(&png))
}

/// About `target` bytes of mixed, ordinary, secret-free text.
fn corpus(target: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed);
    let mut out = String::with_capacity(target + 8192);
    while out.len() < target {
        match r.below(9) {
            0 => out.push_str(RUST),
            1 => out.push_str(PYTHON),
            2 => out.push_str(CONFIG),
            3 => out.push_str(PROSE),
            4 => (0..20).for_each(|_| out.push_str(&package_lock(&mut r))),
            5 => (0..20).for_each(|_| out.push_str(&cargo_lock(&mut r))),
            6 => (0..20).for_each(|_| out.push_str(&yarn_lock(&mut r))),
            7 => out.push_str(&minified_js(&mut r)),
            _ => out.push_str(&image_data_uri(&mut r)),
        }
    }
    out.into_bytes()
}

fn assert_clean(name: &str, data: &[u8]) {
    let f = scan(data);
    assert!(f.is_empty(), "{name}: false positive(s): {f:?}");
}

#[test]
fn ordinary_source_code_is_not_flagged() {
    assert_clean("rust", RUST.as_bytes());
    assert_clean("python", PYTHON.as_bytes());
    assert_clean("prose", PROSE.as_bytes());
}

#[test]
fn config_with_placeholders_and_references_is_not_flagged() {
    for line in CONFIG.lines() {
        assert_clean(line, line.as_bytes());
    }
    assert_clean("config", CONFIG.as_bytes());
}

#[test]
fn lock_files_are_not_flagged() {
    let mut r = Rng(7);
    let npm: String = (0..2000).map(|_| package_lock(&mut r)).collect();
    let cargo: String = (0..2000).map(|_| cargo_lock(&mut r)).collect();
    let yarn: String = (0..2000).map(|_| yarn_lock(&mut r)).collect();
    assert_clean("package-lock.json", npm.as_bytes());
    assert_clean("Cargo.lock", cargo.as_bytes());
    assert_clean("yarn.lock", yarn.as_bytes());
}

#[test]
fn minified_js_is_not_flagged() {
    let mut r = Rng(11);
    let js: String = (0..200).map(|_| minified_js(&mut r)).collect();
    assert_clean("app.min.js", js.as_bytes());
}

#[test]
fn base64_images_and_binary_data_are_not_flagged() {
    let mut r = Rng(13);
    let css: String = (0..500).map(|_| image_data_uri(&mut r)).collect();
    assert_clean("data URIs", css.as_bytes());
    // Random binary (has NUL bytes, so it also goes through the NUL-stripped view).
    for seed in 0..8 {
        let mut r = Rng(100 + seed);
        assert_clean("random binary", &r.bytes(1 << 20));
    }
}

#[test]
fn utf16_ordinary_text_is_not_flagged() {
    let mut utf16 = vec![0xff, 0xfe];
    for u in PYTHON.encode_utf16() {
        utf16.extend_from_slice(&u.to_le_bytes());
    }
    assert_clean("utf-16 python", &utf16);
}

#[test]
fn large_mixed_corpus_is_not_flagged() {
    assert_clean("corpus", &corpus(4 << 20, 1));
}

// ---- detection -------------------------------------------------------------------------

#[test]
fn detects_secrets_in_many_shapes() {
    let cases: &[&[u8]] = &[
        b"password: Xk9mQ2vL7pR4wZt8\n",
        b"DB_PASSWORD=Xk9mQ2vL7pR4wZt8nB3c\n",
        b"export API_KEY=Zt8nB3cXk9mQ2vL7pR4w\n",
        b"spring.datasource.password=Xk9mQ2vL7pR4wZt8\n",
        b"{password: Xk9mQ2vL7pR4wZt8, user: admin}\n",
        b"$db_password = 'Xk9#mQ2$vL7pR4wZ';\n",
        b"'password' => 'Xk9#mQ2$vL7pR4wZ',\n",
        b"connect(host, password=Xk9mQ2vL7pR4wZt8)\n",
        b"aws_key=AKIAIOSFODNN7EXAMPLE\n",
        b"AWS_KEY_AKIAIOSFODNN7EXAMPLE\n",
        b"token_ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n",
        b"\x00\x01\x02AKIAIOSFODNN7EXAMPLE\x00\x00",
    ];
    for c in cases {
        assert!(!scan(c).is_empty(), "missed: {:?}", String::from_utf8_lossy(c));
    }
}

#[test]
fn detects_utf16_big_endian_and_without_bom() {
    let text = "x = 1\r\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\r\n";
    let be: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    let le: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    for (name, data) in [("be", be), ("le", le)] {
        let f = scan(&data);
        assert_eq!(f.len(), 1, "{name}: {f:?}");
        assert_eq!(f[0].line, 2, "{name}");
    }
}

#[test]
fn large_files_are_scanned_everywhere_with_correct_line_numbers() {
    // A secret at the start, across a chunk boundary, and at the very end.
    let mut data = corpus(20 << 20, 3);
    let mid = 4 << 20; // a multiple of any power-of-two chunk size up to 4 MiB
    for (at, s) in [(0, &b"AKIAIOSFODNN7EXAMPLE\n"[..]), (mid - 10, b"\nAKIAIOSFODNN7EXAMPLF\n")] {
        data.splice(at..at, s.iter().copied());
    }
    data.extend_from_slice(b"\nconst k = \"AKIAIOSFODNN7EXAMPLG\";");
    let f = scan(&data);
    let lines: Vec<usize> = f.iter().map(|f| f.line).collect();
    let want = |at: usize| data[..at].iter().filter(|&&b| b == b'\n').count() + 1;
    assert_eq!(lines, vec![1, want(mid - 9), want(data.len() - 5)], "{f:?}");
}

#[test]
fn large_utf16_files_are_scanned_across_chunk_boundaries() {
    let enc = |t: &str| -> Vec<u8> { t.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() };
    let filler = enc("let a = 1;\n"); // 22 bytes, 1 line
    let key = enc("AKIAIOSFODNN7EXAMPLE\n"); // 42 bytes
    let mut data = vec![0xff, 0xfe];
    let mut want = Vec::new();
    let mut line = 1;
    // Keys straddling the 1, 2, 3 and 4 MiB offsets (any power-of-two
    // chunking cuts there), by a varying number of bytes.
    for (mib, into) in [(1usize, 2usize), (2, 20), (3, 40), (4, 41)] {
        while data.len() + filler.len() <= (mib << 20) - into {
            data.extend_from_slice(&filler);
            line += 1;
        }
        data.resize((mib << 20) - into, b' '); // pad to the exact offset (odd padding is fine)
        want.push(line);
        data.extend_from_slice(&key);
        line += 1;
    }
    let f = scan(&data);
    assert_eq!(f.iter().map(|f| f.line).collect::<Vec<_>>(), want, "{f:?}");
}

#[test]
fn findings_are_capped() {
    let data = "AKIAIOSFODNN7EXAMPLE\n".repeat(1000);
    let f = scan(data.as_bytes());
    assert!(!f.is_empty() && f.len() <= 16);
}

// ---- throughput ------------------------------------------------------------------------

fn bench(name: &str, data: &[u8]) {
    let _ = scan(data); // warm up (compiles the regexes)
    let runs = 5;
    let t = Instant::now();
    let mut hits = 0;
    for _ in 0..runs {
        hits += scan(data).len();
    }
    let secs = t.elapsed().as_secs_f64() / runs as f64;
    println!(
        "{name:<28} {:>6.1} MiB  {:>8.2} ms  {:>8.1} MiB/s  ({} finding(s))",
        data.len() as f64 / (1 << 20) as f64,
        secs * 1e3,
        data.len() as f64 / (1 << 20) as f64 / secs,
        hits / runs
    );
}

#[test]
#[ignore = "benchmark"]
fn scanner_throughput() {
    let text = corpus(4 << 20, 1);
    bench("mixed text (clean)", &text);
    let mut r = Rng(5);
    let src: Vec<u8> = (0..(4 << 20) / RUST.len()).flat_map(|_| RUST.bytes()).collect();
    bench("rust source (clean)", &src);
    let mut minjs = Vec::new();
    while minjs.len() < 4 << 20 {
        minjs.extend(minified_js(&mut r).bytes());
    }
    bench("minified js (clean)", &minjs);
    let mut utf16 = vec![0xff, 0xfe];
    for u in String::from_utf8_lossy(&text[..2 << 20]).encode_utf16() {
        utf16.extend_from_slice(&u.to_le_bytes());
    }
    bench("utf-16 text (clean)", &utf16);
    bench("random binary", &r.bytes(4 << 20));
    let mut dirty = text.clone();
    dirty.extend_from_slice(b"\npassword: Xk9mQ2vL7pR4wZt8\nAKIAIOSFODNN7EXAMPLE\n");
    bench("mixed text + 2 secrets", &dirty);
    bench("large mixed text", &corpus(32 << 20, 9));
}

/// Scans every file under `$VEIL_SCAN_DIR` one by one, as snapshots do, and
/// prints throughput and every finding (review them for false positives).
#[test]
#[ignore = "benchmark on a real directory: VEIL_SCAN_DIR=<dir>"]
fn scanner_real_world() {
    let Ok(dir) = std::env::var("VEIL_SCAN_DIR") else { return };
    let mut files = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                files.push((e.path(), std::fs::read(e.path()).unwrap()));
            }
        }
    }
    let total: usize = files.iter().map(|(_, d)| d.len()).sum();
    for (p, d) in &files {
        for f in scan(d) {
            println!("finding: {} {}:{} {}", f.rule, p.display(), f.line, f.excerpt);
        }
    }
    let t = Instant::now();
    for _ in 0..3 {
        for (_, d) in &files {
            std::hint::black_box(scan(d));
        }
    }
    let secs = t.elapsed().as_secs_f64() / 3.0;
    println!("{} files, {:.1} MiB, {:.1} ms, {:.1} MiB/s", files.len(), total as f64 / 1048576.0, secs * 1e3, total as f64 / 1048576.0 / secs);
}
