//! Scanner v6: realistic secrets it misses, ordinary code it quarantines.

use veil_core::secrets::scan;

fn found(data: &[u8]) -> bool {
    !scan(data).is_empty()
}

/// A random-looking 24-character credential.
const S: &str = "q8Zr4XvT2mLpW9nB7kYd3HsJ";

/// Control: the same keys at the start of a line, or quoted, are found.
#[test]
fn camel_case_credential_keys_at_a_line_start_are_found() {
    for text in [format!("_authToken={S}\n"), format!("//registry.npmjs.org/:_authToken=\"{S}\"\n"), format!("accessToken={S}\n")] {
        assert!(found(text.as_bytes()), "{text}");
    }
}

/// Scanner v5 found every one of these; v6 marks `authToken`,
/// `accessToken`, `apiKey`, `clientSecret` found at a camelCase hump as
/// `Key::Strict` (`secrets.rs`, `credential_key`), and a strict key's
/// unquoted value outside a "configuration line" counts as code
/// (`search_with`: `let code = unquoted && !config_line(..) && …`), so the
/// `.npmrc` line every npm user has, and credentials in URL query strings,
/// are no longer found.
#[test]
#[ignore = "BUG-487: scanner v6 misses .npmrc _authToken and ?apiKey= in URLs (v5 found them)"]
fn npmrc_tokens_and_query_string_credentials_are_found() {
    let lines = [
        "//registry.npmjs.org/:_authToken=npm_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5\n".to_string(),
        format!("//npm.pkg.github.com/:_authToken={S}\n"),
        format!("//gitlab.example.com/api/v4/projects/1/packages/npm/:_authToken={S}\n"),
        format!("curl \"https://api.example.com/data?accessToken={S}\"\n"),
        format!("GET /v1/items?apiKey={S} HTTP/1.1\n"),
        format!("webhook=https://example.com/hook?accessToken={S}\n"),
        format!("  url: https://api.example.com/v1?clientSecret={S}\n"),
    ];
    let missed: Vec<&String> = lines.iter().filter(|l| !found(l.as_bytes())).collect();
    assert!(missed.is_empty(), "missed: {missed:?}");
}

/// Java/Spring `.properties` keys separated by dots: `jwt.secret`,
/// `github.token`, `mail.smtp.password` are found, `api.key` and the like
/// are not (the compound keywords and `<WORD>_KEY` only look across `_`).
#[test]
#[ignore = "BUG-488: dotted *.key properties (api.key, stripe.api.key) are missed"]
fn dotted_key_properties_are_found() {
    for key in ["api.key", "stripe.api.key", "aws.secret.key", "google.maps.api.key", "API.KEY"] {
        let text = format!("{key}={S}\n");
        assert!(found(text.as_bytes()), "{text}");
    }
    assert!(found(format!("<entry key=\"api.key\">{S}</entry>\n").as_bytes()));
}

/// Ordinary code that names a credential without holding one. Each of
/// these lines quarantines its file (seen in botocore, twisted, Python's
/// own style), in scanner v5 as in v6.
#[test]
#[ignore = "BUG-489: ordinary code lines are taken for credentials"]
fn ordinary_code_is_not_a_credential() {
    for text in [
        "def check(user):\n    password = lookup(user)\n    return password\n",
        "            password = self.dirdbm[c.username]\n",
        "    if not isinstance(output_token, list):\n        output_token = [output_token]\n",
        "        len_input_token = len(self._input_token)\n",
        "{\n\"password\":{\"type\":\"string\"},\n}\n",
        "pub const XCN_NCRYPT_PCP_ENCRYPTION_KEY: X509HardwareKeyUsageFlags = 2i32;\n",
    ] {
        assert!(scan(text.as_bytes()).is_empty(), "{text}: {:?}", scan(text.as_bytes()));
    }
}
