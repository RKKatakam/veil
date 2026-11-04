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

/// Look-alikes of the rules added for BUG-055 and the backlog: URLs without
/// credentials or with placeholders, `token` / `secret` as ordinary
/// identifiers, CSRF and pagination tokens, metadata about a password, and
/// XML elements that hold no credential.
const LOOKALIKES: &[&str] = &[
    // URLs
    "https://example.com:8443/path?q=1",
    "postgres://db.internal:5432/prod",
    "http://[::1]:8080/health",
    "http://[2001:db8::1]:80/",
    "git@github.com:org/repo.git",
    "ssh://git@host.example.com:22/repo.git",
    "https://user@host.example.com/",
    "DATABASE_URL=postgres://user:password@localhost/db",
    "postgres://postgres:postgres@localhost:5432/test",
    "amqp://guest:guest@rabbitmq:5672//",
    "https://${GIT_USER}:${GIT_TOKEN}@gitlab.com/org/repo.git",
    "redis://:${REDIS_PASSWORD}@redis:6379/0",
    "mysql://root:<password>@127.0.0.1:3306/app",
    "https://user:********@host.example.com",
    "http://admin:changeme@localhost:8080",
    "https://oauth2:$CI_JOB_TOKEN@gitlab.com/group/project.git",
    "url = \"https://deploy:{{ .Values.gitToken }}@git.example.com\"",
    "see http://localhost:3000/@user/profile",
    "mongodb+srv://${MONGO_USER}:${MONGO_PASS}@cluster0.mongodb.net/",
    // token / secret as identifiers
    "let token = tokens.next();",
    "token = lexer.next_token()",
    "tokens: Vec<Token>,",
    "max_tokens = 4096",
    "max_token_length = 2048",
    "token_type: \"Bearer\"",
    "token_url: https://auth.example.com/oauth/token",
    "next_page_token = \"CAESBggBEAEYAQgIEAI\"",
    "nextPageToken: \"CAESBggBEAEYAQgIEAI\"",
    "csrf_token = \"a8f5f167f44f4964e6c998dee827110c\"",
    "<input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">",
    "X-CSRF-Token: 4f8d2a1b9c3e7f60a5b2c9d1",
    "{% csrf_token %}",
    "let cancellation_token = CancellationToken::new();",
    "\"token\": \"<your-token-here>\"",
    "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
    "token: ${{ secrets.NPM_TOKEN }}",
    "mytoken = \"Xk9mQ2vL7pR4wZt8uY3n\"",
    "secret_name: prod-db-credentials",
    "secretName: my-tls-secret",
    "secret_arn = \"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf\"",
    "valueFrom:\n  secretKeyRef:\n    name: db",
    "is_secret = True",
    "SECRET_KEY_BASE: <%= ENV[\"SECRET_KEY_BASE\"] %>",
    "jwt_secret_env: JWT_SECRET_PRODUCTION",
    "topsecret = \"Xk9mQ2vL7pR4wZt8uY3n\"",
    // metadata about a password
    "password_hash = \"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG\"",
    "DB_PASSWORD_FILE=/run/secrets/db_password",
    "password_min_length: 12",
    "password_reset_url: https://example.com/account/reset",
    "PASSWORD_HASHERS = [\"django.contrib.auth.hashers.Argon2PasswordHasher\"]",
    "password_regex = \"^(?=.*[A-Z])(?=.*[0-9]).{12,}$\"",
    "API_KEY_HEADER=X-Api-Key-Primary-2024",
    "DB_PASSWORD_PROD=${DB_PASSWORD_PROD}",
    // XML
    "<password></password>",
    "<password>${db.password}</password>",
    "<password>changeme</password>",
    "<label>Password</label>",
    "<input type=\"password\" name=\"password\">",
    "<passwordPolicy>StrongPasswordPolicy</passwordPolicy>",
    "<password-hash>$2b$12$KIXQJbXk9mQ2vL7pR4wZt8eO</password-hash>",
    "<password>{{ .Values.dbPassword }}</password>",
    "<span class=\"password\">Xk9mQ2vL7pR4wZt8</span>",
];

#[test]
fn credential_lookalikes_are_not_flagged() {
    for l in LOOKALIKES {
        assert_clean(l, l.as_bytes());
    }
    let all = LOOKALIKES.join("\n");
    assert_clean("all look-alikes", all.as_bytes());
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
        // BUG-055 and backlog
        b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        b"DB_PASSWORD_PROD=Xk9mQ2vL7pR4wZt8nB3c\n",
        b"stripe_secret_key_live: Xk9mQ2vL7pR4wZt8nB3c\n",
        b"export API_TOKEN=Xk9mQ2vL7pR4wZt8uY3n\n",
        b"refresh_token: \"Xk9mQ2vL7pR4wZt8uY3n\"\n",
        b"secret: Xk9mQ2vL7pR4wZt8uY3n\n",
        b"webhook-secret = 'Xk9mQ2vL7pR4wZt8uY3n'\n",
        b"mytoken_password = \"Xk9mQ2vL7pR4wZt8\"\n",
        b"<password>Xk9mQ2vL7pR4wZt8</password>\n",
        b"<DbPassword>Xk9mQ2vL7pR4wZt8</DbPassword>\n",
        b"<spring.datasource.password> Xk9mQ2vL7pR4wZt8 </spring.datasource.password>\n",
        b"DATABASE_URL=postgres://app:Xk9mQ2vL7pR4wZt8@db.internal:5432/prod\n",
        b"redis://:Xk9mQ2vL7pR4wZt8@cache:6379/0\n",
        b"git clone https://deploy:s3cr3tP4ss@git.example.com/repo.git\n",
        b"\"url\": \"amqps://svc:Zt8nB3cXk9mQ2vL7@mq.example.com\"\n",
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
fn utf16_without_bom_in_non_latin_scripts_is_scanned() {
    let comment = "設定ファイル。本番環境のデータベース接続。".repeat(50);
    let text = format!("{comment}\r\napi_token = \"Xk9mQ2vL7pR4wZt8uY3n\"\r\n{comment}\r\n");
    for be in [false, true] {
        let data: Vec<u8> = text
            .encode_utf16()
            .flat_map(|u| if be { u.to_be_bytes() } else { u.to_le_bytes() })
            .collect();
        let f = scan(&data);
        assert_eq!(f.len(), 1, "be={be}: {f:?}");
        assert_eq!(f[0].line, 2, "be={be}");
    }
    // Clean CJK text in UTF-16 stays clean.
    let clean: Vec<u8> = format!("{comment}\r\ntoken = tokens.next()\r\n").encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    assert_clean("utf-16 cjk", &clean);
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

// ---- scanner v4: value grammar, more keys, linear time --------------------------------

/// Look-alikes of the rules added for BUG-091 … BUG-095 (`RULES_VERSION` 4):
/// references and templates anywhere in a value, hashes and encrypted
/// values, code that sits where a configuration value would, keys that
/// end in `_key` but hold no secret, URL look-alikes with `:`.
const LOOKALIKES_V4: &[&str] = &[
    // references, templates, placeholders (BUG-091)
    "password: \"$DB_PASSWORD\"",
    "password: \"${DB_PASSWORD:-changeme-later}\"",
    "PASSWORD=\"$(cat /run/secrets/db-password)\"",
    "password: \"{{.Values.db.password}}\"",
    "token: ${{secrets.GITHUB_TOKEN}}",
    "password = \"%(db_password)s\"",
    "password: \"#{ENV['DB_PASSWORD']}\"",
    "password: '%DB_PASSWORD%'",
    "ISCSI_PASSWORD=\"${x#iscsi_password=}\"",
    "password: $HOME/.config/app/password-file",
    "$db_password = $_ENV['DB_PASSWORD'];",
    "$last_update_token = \"\\\"$last_update_token\\\"\";",
    "myURL.password = &#39;123&#39;;",
    "password: <your-database-password>",
    "password: !vault |",
    // hashes and encrypted values
    "password: \"$2b$12$KIXQJbXk9mQ2vL7pR4wZt8eOuLmNp3qRsTuVwXyZaBcDeFgHiJkL\"",
    "password: \"pbkdf2_sha256$600000$abcDEF123$Xk9mQ2vL7pR4wZt8uY3nAbCdEf=\"",
    "userPassword: {SSHA}Xk9mQ2vL7pR4wZt8uY3nAbCd",
    "spring.datasource.password=ENC(G6N718UuyPE5bHyWKyuLQSm02auQPUtm)",
    "password: '{cipher}AQA8x9mQ2vL7pR4wZt8uY3n'",
    "api_key: ENC[AES256_GCM,data:Tr7oXk9mQ2,iv:abc,tag:def,type:str]",
    "password: vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zo",
    // app-password look-alikes, words, numbers, other scripts
    "password: abcd efgh ijkl mnop",
    "password: \"xxxx xxxx xxxx xxxx\"",
    "password: well done good luck",
    "SMTP_PASSWORD=defaultpassword",
    "let encoded_signing_key_too_long = \"[62,70,27,163]\";",
    "password: パスワードを変更します",
    // shapes of BUG-092 that hold no literal
    "define('DB_PASSWORD', getenv('DB_PASSWORD'));",
    "define( 'AUTH_KEY', 'put your unique phrase here' );",
    "__('Password', 'woocommerce-payments')",
    "t('password', 'Enter your password')",
    "os.environ[\"API_KEY\"] = api_key_from_vault",
    "config['password'] = request.form['password']",
    "ENV.fetch('SECRET_KEY') { 'development-secret' }",
    "System.getProperty(\"db.password\", \"\");",
    "env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db",
    "- name: DB_PASSWORD\n  value: \"$(DB_PASS)\"",
    "- name: API_TOKEN\n  value: \"{{ .Values.token }}\"",
    "PASSWORDS_MATCH=true",
    "API_KEYS_FILE=/run/secrets/api-keys",
    "<password type=\"hash\"></password>",
    "<password><![CDATA[${db.password}]]></password>",
    "<key>PasswordPolicy</key>\n<string>StrongPasswordPolicy</string>",
    "<key>Password</key>\n<string>${PASSWORD}</string>",
    "<add key=\"PasswordLength\" value=\"12\"/>",
    "ALTER USER app WITH PASSWORD :'pw';",
    "CREATE USER app IDENTIFIED BY '${DB_PASS}';",
    "APP_KEY=",
    "cache_key = \"a8f5f167f44f4964e6c998dee827110c\"",
    "PUBLIC_KEY=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
    "SIGNING_KEY_PATH=/etc/keys/signing.pem",
    "encryption_key_id = \"arn:aws:kms:us-east-1:123456789012:key/abc\"",
    "whatsappkey = \"Xk9mQ2vL7pR4wZt8uY3n\"",
    // code where a configuration value would be
    "    secret_key = config.secret_key.clone();",
    "    password: Option<String>,",
    "    and_token: input.parse()?,",
    "    lt_token: Token![<](span),",
    "    colon_token: <Token![:]>::default(),",
    "    tokens = _generate_tokens_from_c_tokenizer(",
    "    token: \"foo\".into(),",
    "    secret_key: *secret_key,",
    "    _token_start: &Self::Checkpoint,",
    "    shared_secret: SharedSecret<Kem>,",
    "    semaphore_tokens: Rc<Cell<Vec<JobToken>>>,",
    "    tokens: &[AnsiString<'_>],",
    "    secret = _wcsdup(password);",
    "    password = CFDataCreate(kCFAllocatorDefault,",
    "    authkey=process.current_process().authkey)",
    "    Token::Str(\"field0\"),",
    "    TOKEN: import(\"./llhttp/constants\").CharList;",
    "    let tokens = quote::quote! {",
    "    trait Secret: ZeroizeOnDrop + Zeroize {}",
    "pub const SE_PRIVILEGE_USED: TOKEN_PRIVILEGES_ATTRIBUTES = 2147483648u32;",
    "_non_token_end_matcher = re.compile(r\"[^{}]+\".format(",
    // URLs (BUG-093)
    "cvs://:pserver:anoncvs@sources.redhat.com:/cvs/src",
    "https://user:%24%7BGIT_PASSWORD%7D@git.example.com/repo.git",
    "{\"url\":\"postgres:\\/\\/user:password@localhost\\/db\"}",
    "ssh://git@host.example.com:2222/org/repo.git",
];

#[test]
fn credential_lookalikes_of_v4_rules_are_not_flagged() {
    for l in LOOKALIKES_V4 {
        assert_clean(l, l.as_bytes());
    }
    assert_clean("all v4 look-alikes", LOOKALIKES_V4.join("\n").as_bytes());
}

#[test]
fn detects_v4_shapes() {
    let jwt = format!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ{}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ".repeat(12));
    let long_value = format!("FIREBASE_API_KEY={}\n", "Xk9mQ2vL7pR4wZt8uY3n".repeat(30));
    let cases: Vec<String> = [
        "<add key=\"DbPassword\" value=\"Xk9mQ2vL7pR4wZt8\"/>\n",
        "SMTP_PASSWORD=qzvx kwpr mtfh jlnb\n",
        "smtp:\n  password: \"qzvx kwpr mtfh jlnb\"\n",
        "CREATE USER 'app'@'%' IDENTIFIED BY 'Xk9mQ2vL7pR4wZt8';\n",
        "CREATE ROLE app WITH ENCRYPTED PASSWORD 'Xk9mQ2vL7pR4wZt8';\n",
        "environment:\n  - \"DB_PASSWORD=Xk9#mQ2(vL7pR4wZt8\"\n",
        "export API_KEY='$Xk9mQ2vL7pR4wZt8'\n",
        "password: Xk9mQ2vL7pR4wZt8 # production\n",
        "DefaultEndpointsProtocol=https;AccountName=prod;AccountKey=Zq8vXk9mQ2vL7pR4wZt8aB3cD5eF7gH9==;EndpointSuffix=core.windows.net\n",
        "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=Zq8vXk9mQ2vL7pR4wZt8aB3c=\n",
        "define('NONCE_SALT', 'q8|Zp]x%Wc+Ly~Bv&Hn4Rt7Dj2Mk9Gs5Ef1Aw6Uz');\n",
        "secret_key_base: 9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015\n",
        "firebase: { appKey: \"Zq8vXk9mQ2vL7pR4wZt8aB3c\" }\n",
        "DB_PASSWORD=\"Xk9m${Q2v}L7pR4wZt8\"\n",
        "password: '@Xk9mQ2vL7pR4wZt8'\n",
        "spring.datasource.password=Xk9(mQ2)vL7[pR4]wZt8\n",
        "password = \"Xk9mQ2vL7pR4wZt8\\\\\"\n",
        "token: 'Xk9mQ2''vL7pR4wZt8'\n",
        "DATABASE_URL=mysql://app:Xk9%40mQ2vL7pR4@db.example.com/app\n",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([format!("token: {jwt}\n"), format!("const t = \"{jwt}\";\n"), long_value])
    .collect();
    for c in &cases {
        assert!(!scan(c.as_bytes()).is_empty(), "missed: {c:?}");
    }
}

#[test]
fn a_line_value_and_its_token_are_reported_once() {
    let f = scan(b"x = 1\nDB_PASSWORD=Xk9mQ2vL7pR4wZt8nB3c\n");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].line, 2);
}

/// BUG-094: in UTF-16/32 a non-ASCII character next to ASCII text becomes
/// a space in the NUL-stripped view; line numbers are kept.
#[test]
fn utf16_cjk_glued_to_tokens_keeps_line_numbers() {
    let text = "設定ファイル\r\nアクセスキーAKIAIOSFODNN7EXAMPLE\r\n令牌ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ。\r\n";
    for be in [false, true] {
        let data: Vec<u8> = text.encode_utf16().flat_map(|u| if be { u.to_be_bytes() } else { u.to_le_bytes() }).collect();
        let lines: Vec<usize> = scan(&data).iter().map(|f| f.line).collect();
        assert_eq!(lines, vec![2, 3], "be={be}");
    }
    // Clean Japanese and Chinese text glued to ASCII words stays clean.
    let clean = "設定ファイルtoken数据库password连接。\r\nアクセスAKIAキー\r\n".repeat(50);
    let data: Vec<u8> = clean.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    assert_clean("utf-16 cjk glued to words", &data);
}

/// BUG-095: archives that store files uncompressed (`.tar`, `.zip` with
/// stored entries) hold the file's bytes as they are, so every rule sees
/// them. A PEM header whose newline is escaped (`\n` in JSON) counts inside
/// binary data when key material follows; a bare escaped header does not.
#[test]
fn uncompressed_archive_members_are_scanned() {
    let key = "{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\\n-----END PRIVATE KEY-----\\n\"}";
    let mut zip = b"PK\x03\x04\x0a\0\0\0\0\0\0\0\0\0".to_vec();
    zip.extend_from_slice(&[0; 16]);
    zip.extend_from_slice(b"sa.json");
    zip.extend_from_slice(key.as_bytes());
    zip.extend_from_slice(b"PK\x01\x02\0\0\0\0");
    assert!(!scan(&zip).is_empty(), "service-account key in a stored zip entry");
    let mut binary = b"\x7fELF\0\0\0\0".to_vec();
    binary.extend_from_slice(b"\"-----BEGIN PRIVATE KEY-----\\n\"\0\0parse error\0");
    assert_clean("a bare escaped header in a program", &binary);
}

/// BUG-090: a search that spends more than `WORK_FACTOR` times its input
/// on restarts inside rejected matches stops and reports `scan-limit`
/// (which quarantines the file). Ordinary text with many rejected
/// candidates stays far below the limit.
#[test]
fn crafted_input_is_reported_and_ordinary_input_is_not() {
    let crafted = "xtoken=".repeat(40_000);
    assert!(scan(crafted.as_bytes()).iter().any(|f| f.rule == "scan-limit"));
    let mut dense = String::new();
    for i in 0..20_000 {
        dense.push_str(&format!("csrf_token={i:08}abcdefgh\nX_PASSWORD=${{DATABASE_PASSWORD_{i}}}\nmytoken_x = \"ghp_short\"\n"));
    }
    assert_clean("dense rejected candidates", dense.as_bytes());
}

/// Inputs crafted against the scanner's worst case (repeated token
/// prefixes after a byte that rejects them, near-miss tokens, assignment
/// runs, long runs of one byte) take time linear in their size: 8 times the
/// input must not take much more than 8 times as long. (The quadratic
/// scanner of BUG-090 took 64 times as long, and minutes at 256 KiB.)
#[test]
fn scanning_time_is_linear_on_crafted_input() {
    let units = [
        "xgithub_pat_", "xsk-", "xsk-ant-", "xglpat-", "xxoxb-", "xsk_live_", "xAIza", "xeyJ", "-eyJ-AKIAIOSFODNN7EXAMPLEZ-", "XAKIA", "://a:",
        ":\\/\\/a:", "ghp_", "-----BEGIN PRIVATE KEY-----", "xtoken=", "csrf_token=", "password_url=", "password=", "password=\"", "password='",
        "<password>", "<password a=\"b\">", "'password', '", "- name: password\n  value: ", "with password '", "password_x_x_x_x_x_x_x=",
        "xapp_key=", "a", "password", " ", "\\", "\"", "${{", "%(", "password: x\n", "password=a(b)\n", "xtoken=Xk9mQ2vL7pR4wZt8,",
        "<key>password</key><string>", "identified by '", "password=:", "password: [", "password: abcd ",
        // scanner v6
        "xKey=", "aKey=\"", "a_key=", "githubToken=", "githubToken: '", "KeY3=", "pwd=", "a=`", "apiKey: string = \"",
        "<entry key=\"password\">", "<a key=\"password\" b=\"c\">", "tokenizer=", "passwordX=", "\nkey=", "\na_key=x",
    ];
    let time = |data: &[u8]| {
        let t = Instant::now();
        std::hint::black_box(scan(data));
        t.elapsed()
    };
    let mut report = Vec::new();
    for unit in units {
        let make = |n: usize| unit.repeat(n / unit.len() + 1).into_bytes()[..n].to_vec();
        let (small, large) = (make(32 << 10), make(256 << 10));
        let ts = time(&small).min(time(&small));
        let tl = time(&large);
        if tl > ts * 24 + std::time::Duration::from_millis(300) {
            report.push(format!("{unit:?}: 32 KiB {ts:?}, 256 KiB {tl:?}"));
        }
    }
    assert!(report.is_empty(), "superlinear:\n{}", report.join("\n"));
}

// ---- scanner v6: camelCase keys, more `*_KEY` names, XML attributes ------------------

const V6_VALUE: &str = "Xk9mQ2vL7pR4wZt8uY3n";

/// `key` = `v` in every format the v6 key rules cover: JSON, YAML, JS and
/// TS objects and properties, a typed TS property, a template literal,
/// `.properties`, an XML attribute.
fn v6_formats(key: &str, v: &str) -> Vec<String> {
    vec![
        format!("{{\"{key}\": \"{v}\"}}\n"),
        format!("{{\n  \"name\": \"app\",\n  \"{key}\": \"{v}\",\n  \"debug\": false\n}}\n"),
        format!("{key}: {v}\n"),
        format!("services:\n  github:\n    {key}: '{v}'\n"),
        format!("const config = {{ {key}: \"{v}\", debug: false }};\n"),
        format!("module.exports = {{\n  {key}: '{v}',\n}};\n"),
        format!("this.{key} = \"{v}\";\n"),
        format!("config.{key} = '{v}';\n"),
        format!("  private readonly {key}: string = \"{v}\";\n"),
        format!("export const {key} = `{v}`;\n"),
        format!("app.{key}={v}\n"),
        format!("<config {key}=\"{v}\" />\n"),
    ]
}

/// Generic token keys in camelCase and PascalCase (`githubToken: …`), in
/// every format (scanner v6).
#[test]
fn camel_case_keys_are_found_in_every_format() {
    let keys = [
        "githubToken", "GithubToken", "apiKey", "ApiKey", "stripeSecret", "authToken", "accessKey", "clientSecret", "slackBotToken",
        "npmAuthToken", "sessionSecret", "refreshToken", "stripeSecretKey", "licenseKey", "signingKey", "masterKey", "apiKeyProd",
        "dbPasswordProd", "githubTokenV2", "openAIKey", "APIToken", "dbPwd",
    ];
    let mut missed = Vec::new();
    for key in keys {
        for c in v6_formats(key, V6_VALUE) {
            if scan(c.as_bytes()).is_empty() {
                missed.push(c);
            }
        }
    }
    assert!(missed.is_empty(), "missed:\n{}", missed.join(""));
}

/// `*_KEY` names beyond the common ones, and any `<WORD>_KEY` with a random
/// value, in dotenv, shell, YAML, JSON, Python and Kubernetes form.
#[test]
fn more_key_names_are_found() {
    let keys = [
        "STRIPE_API_KEY", "AWS_SECRET_KEY", "JWT_PRIVATE_KEY", "MINIO_ACCESS_KEY", "COSIGN_SIGNING_KEY", "VAULT_MASTER_KEY",
        "DB_ENCRYPTION_KEY", "SIDEKIQ_LICENSE_KEY", "MAPBOX_KEY", "SENDGRID_KEY", "OPENAI_KEY", "ALGOLIA_ADMIN_KEY", "SEGMENT_WRITE_KEY",
        "TWILIO_KEY", "SESSION_KEY", "WEBHOOK_KEY",
    ];
    let mut missed = Vec::new();
    for key in keys {
        let v = V6_VALUE;
        for c in [
            format!("{key}={v}\n"),
            format!("export {key}=\"{v}\"\n"),
            format!("{key}: {v}\n"),
            format!("{{\"{key}\": \"{v}\"}}\n"),
            format!("{key} = \"{v}\"\n"),
            format!("os.environ[\"{key}\"] = \"{v}\"\n"),
            format!("environment:\n  - {key}={v}\n"),
            format!("env:\n  - name: {key}\n    value: \"{v}\"\n"),
            format!("ENV {key}={v}\n"),
        ] {
            if scan(c.as_bytes()).is_empty() {
                missed.push(c);
            }
        }
    }
    assert!(missed.is_empty(), "missed:\n{}", missed.join(""));
}

/// XML attributes other than `value` on any element, connection strings,
/// and elements whose key is an attribute (Java's `<entry key=…>`, Spring,
/// .NET settings).
#[test]
fn xml_attributes_and_connection_strings_are_found() {
    let v = "Xk9mQ2vL7pR4wZt8";
    let cases = [
        format!("<user name=\"admin\" password=\"{v}\"/>\n"),
        format!("<datasource url=\"jdbc:postgresql://db/app\" password='{v}' />\n"),
        format!("<credentials secret=\"{v}uY3n\"/>\n"),
        format!("<auth token=\"{v}uY3n\"></auth>\n"),
        format!("<service apiKey=\"{v}uY3n\" />\n"),
        format!("<Credential Password=\"{v}\" />\n"),
        format!("<smtp\n    host=\"mail.example.com\"\n    password=\"{v}\"/>\n"),
        format!("<add name=\"Default\" connectionString=\"Server=db;Database=app;User Id=sa;Password={v};\" providerName=\"System.Data.SqlClient\"/>\n"),
        format!("<add name=\"Default\" connectionString=\"Data Source=db;Initial Catalog=app;User ID=sa;Pwd={v}\" />\n"),
        format!("<entry key=\"db.password\">{v}</entry>\n"),
        format!("<entry key=\"apiToken\">{v}uY3n</entry>\n"),
        format!("<property name=\"password\"><value>{v}</value></property>\n"),
        format!("<setting name=\"ApiKey\" serializeAs=\"String\">\n  <value>{v}uY3n</value>\n</setting>\n"),
        format!("<add key=\"StripeSecretKey\" value=\"{v}uY3n\"/>\n"),
    ];
    let missed: Vec<&String> = cases.iter().filter(|c| scan(c.as_bytes()).is_empty()).collect();
    assert!(missed.is_empty(), "missed: {missed:#?}");
}

/// Declarations with a string type (Rust, TypeScript, Python, Kotlin).
#[test]
fn typed_declarations_are_found() {
    let v = V6_VALUE;
    let cases = [
        format!("const API_KEY: &str = \"{v}\";\n"),
        format!("pub const API_KEY: &'static str = \"{v}\";\n"),
        format!("    api_key: str = \"{v}\"\n"),
        format!("    api_key: SecretStr = \"{v}\"\n"),
        format!("  apiKey: string = '{v}';\n"),
        format!("val githubToken: String = \"{v}\"\n"),
        format!("let apiKey: String = \"{v}\"\n"),
    ];
    let missed: Vec<&String> = cases.iter().filter(|c| scan(c.as_bytes()).is_empty()).collect();
    assert!(missed.is_empty(), "missed: {missed:#?}");
}

/// Look-alikes of the v6 rules (`RULES_VERSION` 6): identifiers that only
/// contain a keyword, camelCase names of things other than credentials,
/// Hungarian notation, type annotations, schemas, keys that are not
/// secrets, base64 that looks like camelCase, HTML's `accesskey`.
const LOOKALIKES_V6: &[&str] = &[
    // camelCase
    "const tokenizer = new Tokenizer(options);",
    "tokenizer: \"Xk9mQ2vL7pR4wZt8uY3n\"",
    "passwordless = \"Xk9mQ2vL7pR4wZt8uY3n\"",
    "const passwordField = \"Xk9mQ2vL7pR4wZt8uY3n\";",
    "keyboard: \"Xk9mQ2vL7pR4wZt8uY3n\"",
    "monkey = \"Xk9mQ2vL7pR4wZt8uY3n\"",
    "hotkey: \"ctrl+shift+k\"",
    "csrfToken: \"a8f5f167f44f4964e6c998dee827110c\"",
    "XSRFToken = \"a8f5f167f44f4964e6c998dee827110c\"",
    "cancellationToken = CancellationToken.None;",
    "tokenType: \"Bearer\"",
    "passwordHash: \"$2b$12$KIXQJbXk9mQ2vL7pR4wZt8eOuLmNp3qRsTuVwXyZaBcDeFgHiJkL\"",
    "tokenUrl: \"https://auth.example.com/oauth/token\"",
    "passwordMinLength: 12",
    "maxTokens: 4096",
    "isSecret: true",
    "secretName: \"prod-db-credentials\"",
    "authTokenHeader: \"X-Auth-Token-Primary\"",
    "lastSignificantToken = \"?InterpolationInTemplate\";",
    "const looseLowPriorityKey = \"@babel/plugin-class-features/looseLowPriorityKey\";",
    "var keysFunc=isFull?isFlat?getAllKeysIn:getAllKeys:isFlat?keysIn:keys;",
    "\"TokenValue\":{\"type\":\"long\"},",
    "\"EncryptionKey\":{\"shape\":\"EncryptionKey\"},",
    "\"PasswordLastUsed\": \"2016-09-08T21:47:36Z\",",
    "\"ClientToken\": \"abcd12f2-46da-4fdb-b8d5-fbd4c466928f\",",
    "\"SecretString\": \"{\\\"username\\\":\\\"david\\\",\\\"password\\\":\\\"EXAMPLE-PASSWORD\\\"}\"",
    // Hungarian notation and code on a line of its own
    "  nToken = pOp->p4.nToken;",
    "  pKeyInfo = pOp->p4.pKeyInfo;",
    "  iKey = sqlite3VdbeIntValue(pIn1);",
    "    primary_result_key = self.result_keys[0]",
    "    data__readme_keys = set(data__readme.keys())",
    "    self._invoking_user_pwd = pwd.getpwuid(os.getuid())",
    "    redacted_key_value = f\"{key}=REDACTED\"",
    // type annotations
    "    pub GenerateKey: BCryptGenerateSymmetricKeyFn,",
    "    pub PresentHistoryToken: D3DKMT_PRESENTHISTORYTOKEN,",
    "    pub CompleteAuthToken: SpCompleteAuthTokenFn,",
    "  apiKey: string;",
    "  apiKey?: string,",
    "const API_KEY: &str = env!(\"API_KEY\");",
    "    api_key: Optional[str] = None",
    "export const githubToken = `${process.env.GITHUB_TOKEN}`;",
    // `pwd`
    "OLDPWD=/home/user/src",
    "PWD=/home/user/src/app",
    "PWD: &#39;/Users/maciej&#39;,",
    // base64 that looks like a camelCase key
    "  integrity sha1-UcM5S2Lmjke+eUE6xXD5KeY3ImI=\n\n\"@babel/core@^7.21.0\":",
    "  integrity sha1-UcM5S2LmjkeAbcKey3=\n\n\"@babel/core@^7.21.0\":",
    // keys that are not secrets
    "PRIMARY_KEY = \"user_id\"",
    "SORT_KEY: created_at",
    "FOREIGN_KEY_CHECKS=0",
    "KEY_PREFIX = \"myapp:sessions:\"",
    "REDIS_KEY_PREFIX=app_cache_v2_",
    "partitionKey: \"/tenantId\"",
    "primaryKey: true",
    "sortKey: \"createdAt#2024\"",
    "hashKey: 'pk'",
    "publicKey: \"BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkrxZJjSgSnfckjBJuBkr3qBUYIHBQFLXYp5Nksh8U\"",
    "VAPID_PUBLIC_KEY=BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkrxZJjSgSnfckjBJuBkr3qBUYIHBQFLXYp5Nksh8U",
    "STRIPE_PUBLISHABLE_KEY=pk_live_51H8xXk9mQ2vL7pR4wZt8uY3n",
    "RECAPTCHA_SITE_KEY=6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
    "GPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D",
    "idempotencyKey: \"123e4567-e89b-12d3-a456-426614174000\"",
    "ROW_KEY = \"123e4567-e89b-12d3-a456-426614174000\"",
    "objectKey: \"uploads/2024/01/avatar.png\"",
    "routing_key = \"events.user.created\"",
    "translationKey: 'settings.password.title'",
    "storageKey: \"app.preferences.v2\"",
    "S3_KEY=my-app/22a0-stage-150819_185942.war",
    "MAPBOX_KEY=changeme-in-production",
    "STRIPE_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxxxxx",
    "DEPLOY_KEY_PATH=/etc/keys/deploy",
    "ssh_key_fingerprint: \"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8\"",
    "LICENSE_KEY_URL=https://example.com/license",
    "SIGNING_KEY_ID=7F2D347EA6AA65421D",
    "\"result_key\": \"Ipv6CidrAssociations\"",
    "_key = \"Xk9mQ2vL7pR4wZt8uY3n\"",
    "<li><a href=\"genindex.html\" accesskey=\"I\">index</a></li>",
    // XML
    "<entry key=\"password.min.length\">12</entry>",
    "<entry key=\"db.password\">${DB_PASSWORD}</entry>",
    "<label for=\"password\">Password</label>",
    "<div class=\"token\">Xk9mQ2vL7pR4wZt8uY3n</div>",
    "<property name=\"passwordEncoder\" ref=\"bcrypt\"/>",
    "<add key=\"ApiKeyHeader\" value=\"X-Api-Key-Primary-2024\"/>",
    "<add name=\"Default\" connectionString=\"Server=db;Database=app;Integrated Security=true\"/>",
    "<user name=\"admin\" password=\"${ADMIN_PASSWORD}\"/>",
];

#[test]
fn credential_lookalikes_of_v6_rules_are_not_flagged() {
    for l in LOOKALIKES_V6 {
        assert_clean(l, l.as_bytes());
    }
    assert_clean("all v6 look-alikes", LOOKALIKES_V6.join("\n").as_bytes());
}

/// A window of the chunked passes that starts inside a line does not make
/// the rest of that line a configuration line: every chunk boundary of a
/// file of code lines is tried.
#[test]
fn a_chunk_boundary_inside_a_code_line_is_not_a_configuration_line() {
    let line = "    client = Client(api_key=api_key, password=password, auth_token=access_token)\n";
    for shift in 0..line.len() {
        let mut data = " ".repeat(shift);
        while data.len() < (256 << 10) + 4 * line.len() {
            data.push_str(line);
        }
        assert_clean(&format!("shift {shift}"), data.as_bytes());
    }
}

/// The v6 rules hold in UTF-16 and in binary data (a `.tar` of a dotenv
/// file), and where the pre-filter limits the search: the only keyword at
/// the very start or end of a large file, a Kubernetes `value:` after the
/// last keyword line.
#[test]
fn v6_rules_hold_in_every_encoding_and_place() {
    let v = V6_VALUE;
    let utf16: Vec<u8> = format!("{{\r\n  \"githubToken\": \"{v}\"\r\n}}\r\n").encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(!scan(&utf16).is_empty(), "utf-16");
    let mut tar = b"deploy/.env\0".to_vec();
    tar.resize(512, 0);
    tar.extend_from_slice(format!("MAPBOX_KEY={v}\nspring.datasource.password=Xk9(mQ2)vL7[pR4]wZt8\n").as_bytes());
    tar.resize(2048, 0);
    let f = scan(&tar);
    assert_eq!(f.len(), 2, "tar: {f:?}");
    let filler = "let a = b + c; // ordinary code without credentials\n".repeat((1 << 20) / 50);
    for (name, data) in [
        ("first line", format!("apiKeyProd: \"{v}\"\n{filler}")),
        ("last line", format!("{filler}MAPBOX_KEY={v}")),
        ("k8s after the last keyword", format!("{filler}env:\n  - name: DB_PASSWORD\n    value: \"{v}\"\n{filler}")),
    ] {
        assert!(!scan(data.as_bytes()).is_empty(), "{name}");
    }
}

// ---- scanner v7 (BUG-487 … BUG-489) --------------------------------------------------

/// Credential keys, as words, in the shapes `v5_key_spellings` writes them.
const V5_KEYS: &[&str] = &[
    "password", "passwd", "secret", "token", "api key", "secret key", "secret access key", "aws secret access key", "client secret",
    "access token", "auth token", "private key", "app key", "master key", "rails master key", "encryption key", "signing key", "auth key",
    "db password", "smtp password", "jwt secret", "github token", "gitlab token", "slack token", "stripe secret key", "x api key",
    "my api key", "refresh token", "bearer token", "oauth token", "session secret", "client secret prod", "account key",
    "shared access key", "admin password", "secret token", "api token", "personal access token", "npm token", "auth token prod",
    "db password 2", "api keys", "passwords", "app secret", "consumer secret", "access key secret", "hmac key", "logged in salt",
    "nonce salt", "webhook secret", "root password", "mysql root password",
];

/// Spellings of `V5_KEYS` scanner v5 did not take for credentials: a
/// generic `secret` / `token` glued to another word (`githubtoken`, a
/// camelCase `githubToken`), and `railsmasterkey`.
const V5_MISSED_KEYS: &[&str] = &[
    "AccessKeySecret", "ApiToken", "AppSecret", "AuthTokenProd", "BearerToken", "ClientSecretProd", "ConsumerSecret", "GithubToken",
    "GitlabToken", "JwtSecret", "NpmToken", "RefreshToken", "SecretToken", "SessionSecret", "SlackToken", "WebhookSecret",
    "_accessKeySecret", "_apiToken", "_appSecret", "_authTokenProd", "_bearerToken", "_clientSecretProd", "_consumerSecret",
    "_githubToken", "_gitlabToken", "_jwtSecret", "_npmToken", "_refreshToken", "_secretToken", "_sessionSecret", "_slackToken",
    "_webhookSecret", "accessKeySecret", "accesskeysecret", "apiToken", "apitoken", "appSecret", "appsecret", "authTokenProd",
    "authtokenprod", "bearerToken", "bearertoken", "clientSecretProd", "clientsecretprod", "consumerSecret", "consumersecret",
    "githubToken", "githubtoken", "gitlabToken", "gitlabtoken", "jwtSecret", "jwtsecret", "npmToken", "npmtoken", "railsmasterkey",
    "refreshToken", "refreshtoken", "secretToken", "secrettoken", "sessionSecret", "sessionsecret", "slackToken", "slacktoken",
    "webhookSecret", "webhooksecret",
];

/// Where keys and values occur: configuration, code, URLs, `.npmrc`, XML.
const V5_CONTEXTS: &[&str] = &[
    "{k}={v}", "{k}: {v}", "  {k}: \"{v}\"", "\"{k}\": \"{v}\",", "export {k}=\"{v}\"", "{k} = '{v}'", "    {k} = \"{v}\"",
    "const {k} = \"{v}\";", "client = Client({k}=\"{v}\")", "client = Client({k}={v})", "https://api.example.com/x?{k}={v}&a=b",
    "curl \"https://api.example.com/x?a=b&{k}={v}\"", "//registry.npmjs.org/:{k}={v}", "<{k}>{v}</{k}>", "<add key=\"{k}\" value=\"{v}\"/>",
    "    '{k}' => '{v}',", "ENV {k}={v}", "set {k}={v}", "{k}:={v}", "obj.{k} = \"{v}\"", "this.{k} = '{v}';", "config['{k}'] = '{v}'",
    "os.environ[\"{k}\"] = \"{v}\"", "define('{k}', '{v}');", "- name: {k}\n  value: \"{v}\"", "{k}={v} # comment", "{\"{k}\":\"{v}\"}",
    "--{k}={v}", "  - \"{k}={v}\"", "  {k}: {v}", "$ {k}={v} ./run", "<property name=\"{k}\" value=\"{v}\"/>", "{k} := \"{v}\"",
    "let {k} = \"{v}\";", "headers = {\"{k}\": \"{v}\"}", "{k} = {v}", "fetch(url + \"?{k}={v}\")", "\"url\": \"https://x.com/?{k}={v}\"",
    "  url: https://api.example.com/v1?{k}={v}", "GET /v1/items?{k}={v} HTTP/1.1", "webhook=https://example.com/hook?{k}={v}",
    "x = f(a, {k}={v})", "{k}=\"{v}\"", "[default]\n{k} = {v}", "<{k} type=\"plain\">{v}</{k}>", "  {k}={v}", "\t{k}\t=\t{v}", "{k}={v};",
    "{k}: '{v}'", "server.{k}={v}", "spring.datasource.{k}={v}",
];

/// Random credentials of several kinds: alphanumeric, with symbols, hex,
/// base64, lower-case, an npm token, short, dashed.
const V5_VALUES: &[&str] = &[
    "q8Zr4XvT2mLpW9nB7kYd3HsJ", "Xk9#mQ2$vL7pR4wZ", "9f86d081884c7d659a2feaa0c55ad015", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2Rl",
    "qzvxkwprmtfhjlnb", "npm_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5", "Xk9mQ2vL7pR4", "Xk9m-Q2vL-7pR4-wZt8",
];

/// `words` as `snake_case`, `SNAKE_CASE`, `kebab-case`, `camelCase`,
/// `PascalCase`, `flatcase` and `_camelCase`.
fn v5_key_spellings(words: &[&str]) -> Vec<String> {
    let cap = |w: &str| w[..1].to_uppercase() + &w[1..];
    let camel = words[0].to_string() + &words[1..].iter().map(|w| cap(w)).collect::<String>();
    let mut out = vec![
        words.join("_"),
        words.join("_").to_uppercase(),
        words.join("-"),
        camel.clone(),
        words.iter().map(|w| cap(w)).collect(),
        words.concat(),
        format!("_{camel}"),
    ];
    out.sort();
    out.dedup();
    out
}

/// BUG-487: every shape scanner v5 found is still found. The corpus is
/// every spelling of `V5_KEYS` in every context of `V5_CONTEXTS` (2,700
/// shapes, 14,200 lines with the value rotating); scanner v5 found every
/// one but the `V5_MISSED_KEYS` spellings, whatever the value (measured
/// with v5's `secrets.rs`, commit `bf824d0~1`, on all 8 values of each
/// shape), and v6 missed 1,176 of them (unquoted values of camelCase keys:
/// `.npmrc`, query strings, kwargs; `secretKey`; `API_KEYS`).
#[test]
fn every_shape_scanner_v5_found_is_found() {
    let mut missed = Vec::new();
    let mut n = 0;
    for (ki, key) in V5_KEYS.iter().flat_map(|k| v5_key_spellings(&k.split(' ').collect::<Vec<_>>())).enumerate() {
        if V5_MISSED_KEYS.contains(&key.as_str()) {
            continue;
        }
        for (ci, context) in V5_CONTEXTS.iter().enumerate() {
            let v = V5_VALUES[(ki + ci) % V5_VALUES.len()];
            let line = format!("{}\n", context.replace("{k}", &key).replace("{v}", v));
            n += 1;
            if scan(line.as_bytes()).is_empty() {
                missed.push(line);
            }
        }
    }
    assert!(n > 14_000, "{n}");
    assert!(missed.is_empty(), "{} of {n} missed, e.g. {:?}", missed.len(), &missed[..missed.len().min(10)]);
}

/// BUG-488: dotted keys count where a key starts a configuration line or
/// names an XML entry, not in code (`obj.key = …`) unless the value is a
/// literal random enough for a key.
#[test]
fn dotted_keys_count_in_configuration_only() {
    let v = "q8Zr4XvT2mLpW9nB7kYd3HsJ";
    for text in [
        format!("api.key={v}\n"),
        format!("  stripe.api.key: \"{v}\"\n"),
        format!("app.encryption.key = {v}\n"),
        format!("csrf.token.secret={v}\n"),
        format!("<add key=\"Stripe.Api.Key\" value=\"{v}\" />\n"),
        format!("<property name=\"mail.api.key\" value=\"{v}\"/>\n"),
        format!("<entry key='aws.secret.key'>{v}</entry>\n"),
    ] {
        assert!(!scan(text.as_bytes()).is_empty(), "{text}");
    }
    for text in [
        "obj.key = getKey();\n",
        "self.key = key\n",
        "this.key = options.key;\n",
        "item.key = \"user-profile-cache\"\n",
        "cache.key = make_key(user.id, 'profile')\n",
        "csrf.token=abcdefghijklmnopqrstuvwxyz0123456789\n",
        "primary.key=customer_id_and_order_number\n",
        "jwt.secret.path=/run/secrets/jwt_signing_secret\n",
        "if (obj.api.key == expected) { return obj.api.key; }\n",
        "<entry key=\"api.key.header\">X-Api-Key-Header-Name</entry>\n",
    ] {
        assert_clean(text, text.as_bytes());
    }
}

/// BUG-489: code made of names is no credential, in any line: calls,
/// indexes, lists, JSON Schema objects, type annotations.
#[test]
fn code_values_are_not_credentials() {
    for text in [
        "    password = lookup(user)\n",
        "    password = self.dirdbm[c.username]\n",
        "    output_token = [output_token]\n",
        "    len_input_token = len(self._input_token)\n",
        "    password = cfg.get(\"password\", default_password)\n",
        "    identity_token = self._web_identity_token_loader()\n",
        "    \"output_token\": \"Jobs[-1].JobId\",\n",
        "    \"Token\":{\"type\":\"string\"},\n",
        "    \"EncryptionKey\":{\"shape\":\"EncryptionKey\"},\n",
        "pub const XCN_NCRYPT_PCP_ENCRYPTION_KEY: X509HardwareKeyUsageFlags = 2i32;\n",
        "    signing_keys = self.get_signing_keys(refresh=True)\n",
        "    passwd = getpass.getpass(b'Password: ')\n",
    ] {
        assert_clean(text, text.as_bytes());
    }
    // Real credentials in the same places are still found, also wrapped.
    for text in [
        "    password = \"Xk9(mQ2)vL7pR4wZt8\"\n",
        "    password = Xk9mQ2vL7pR4wZt8(x)\n",
        "pub const ENCRYPTION_KEY: &str = \"q8Zr4XvT2mLpW9nB7kYd3HsJ\";\n",
        "client = Client(password=Xk9mQ2vL7pR4wZt8)\n",
    ] {
        assert!(!scan(text.as_bytes()).is_empty(), "{text}");
    }
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
    // Worst cases (BUG-090): linear, reported as `scan-limit` where noted.
    for unit in ["xsk-", "xtoken=", "-eyJ-AKIAIOSFODNN7EXAMPLEZ-", "password=", "password=\""] {
        bench(&format!("crafted {unit:?}"), &unit.repeat((4 << 20) / unit.len()).into_bytes());
    }
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

