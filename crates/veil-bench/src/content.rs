//! Deterministic synthetic content: a seeded PRNG, file-size and shape
//! distributions, and generators for source code (zstd ratio about 4),
//! JSON/YAML configuration, and incompressible binaries.
//!
//! Everything here is a pure function of the seed, so two runs of
//! `veil-bench gen` with the same profile and seed write the same files
//! and the same history shape (snapshot and change ids still differ: they
//! carry random change ids, timestamps and signatures).

/// SplitMix64: small, fast, and good enough for benchmark data.
#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    /// An independent stream derived from this seed and `label`.
    pub fn fork(seed: u64, label: u64) -> Rng {
        let mut r = Rng::new(seed.wrapping_mul(0xA24B_AED4_963E_E407) ^ label.wrapping_mul(0x9FB2_1C65_1E98_DF25));
        r.next();
        r
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        ((self.next() >> 11) % n as u64) as usize
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    /// Uniform in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    /// A standard normal sample (Box–Muller).
    pub fn normal(&mut self) -> f64 {
        let u1 = self.unit().max(1e-12);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }

    /// Log-normal with the given median and shape.
    pub fn log_normal(&mut self, median: f64, sigma: f64) -> f64 {
        median * (sigma * self.normal()).exp()
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const WORDS: &[&str] = &[
    "buffer", "index", "node", "tree", "entry", "value", "state", "cache", "store", "frame", "token", "parser",
    "reader", "writer", "stream", "chunk", "block", "range", "offset", "length", "count", "total", "limit",
    "config", "option", "result", "error", "status", "handle", "context", "session", "request", "response",
    "header", "payload", "message", "queue", "worker", "task", "event", "signal", "timer", "clock", "epoch",
    "version", "schema", "record", "table", "column", "row", "field", "key", "map", "set", "list", "vector",
    "matrix", "graph", "edge", "vertex", "path", "route", "target", "source", "input", "output", "filter",
    "sort", "merge", "split", "join", "parse", "encode", "decode", "hash", "digest", "sign", "verify", "seal",
    "open", "close", "flush", "sync", "lock", "unlock", "retry", "backoff", "commit", "rollback", "apply",
    "update", "insert", "delete", "select", "scan", "visit", "walk", "build", "check", "validate", "render",
    "layout", "widget", "panel", "button", "label", "image", "color", "theme", "style", "font", "pixel",
    "user", "account", "profile", "group", "member", "role", "policy", "scope", "grant", "revoke", "audit",
];

const TYPES: &[&str] = &["u8", "u16", "u32", "u64", "usize", "i64", "f64", "bool", "String", "Vec<u8>", "Option<u64>"];

fn ident(rng: &mut Rng) -> String {
    let a = rng.pick(WORDS);
    if rng.chance(0.6) {
        format!("{a}_{}", rng.pick(WORDS))
    } else {
        a.to_string()
    }
}

fn camel(rng: &mut Rng) -> String {
    let mut s = String::new();
    for _ in 0..rng.range(1, 3) {
        let w = rng.pick(WORDS);
        let mut c = w.chars();
        if let Some(f) = c.next() {
            s.push(f.to_ascii_uppercase());
            s.push_str(c.as_str());
        }
    }
    s
}

/// One line of synthetic code in the style of `ext`.
pub fn source_line(rng: &mut Rng, ext: &str, indent: usize) -> String {
    let pad = "    ".repeat(indent);
    let n = rng.below(1000);
    match ext {
        "py" => match rng.below(6) {
            0 => format!("{pad}def {}(self, {}, {}={n}):", ident(rng), ident(rng), ident(rng)),
            1 => format!("{pad}{} = self.{}({}, {n})", ident(rng), ident(rng), ident(rng)),
            2 => format!("{pad}if {} > {n}:", ident(rng)),
            3 => format!("{pad}return {}.{}()", ident(rng), ident(rng)),
            4 => format!("{pad}# {} the {} before {}", rng.pick(WORDS), ident(rng), rng.pick(WORDS)),
            _ => format!("{pad}for {} in {}:", ident(rng), ident(rng)),
        },
        "ts" => match rng.below(6) {
            0 => format!("{pad}export function {}({}: {}): number {{", camel(rng), ident(rng), camel(rng)),
            1 => format!("{pad}const {} = await {}.{}({n});", ident(rng), ident(rng), camel(rng)),
            2 => format!("{pad}if ({}.length > {n}) {{", ident(rng)),
            3 => format!("{pad}return {{ {}: {}, {}: {n} }};", ident(rng), ident(rng), ident(rng)),
            4 => format!("{pad}// {} the {} before {}", rng.pick(WORDS), ident(rng), rng.pick(WORDS)),
            _ => format!("{pad}}}"),
        },
        _ => match rng.below(7) {
            0 => format!("{pad}pub fn {}(&self, {}: {}) -> {} {{", ident(rng), ident(rng), rng.pick(TYPES), rng.pick(TYPES)),
            1 => format!("{pad}let {} = self.{}.{}({n});", ident(rng), ident(rng), ident(rng)),
            2 => format!("{pad}if {} > {n} {{", ident(rng)),
            3 => format!("{pad}{}::{}(&mut {}, {n})?;", camel(rng), ident(rng), ident(rng)),
            4 => format!("{pad}// {} the {} before {}", rng.pick(WORDS), ident(rng), rng.pick(WORDS)),
            5 => format!("{pad}}}"),
            _ => format!("{pad}struct {} {{ {}: {}, {}: {} }}", camel(rng), ident(rng), rng.pick(TYPES), ident(rng), rng.pick(TYPES)),
        },
    }
}

/// A source file of about `size` bytes.
pub fn source_file(rng: &mut Rng, ext: &str, size: usize) -> Vec<u8> {
    let mut s = String::with_capacity(size + 128);
    s.push_str(&format!("// generated by veil-bench: {} module\n", camel(rng)));
    while s.len() < size {
        let indent = rng.below(4);
        s.push_str(&source_line(rng, ext, indent));
        s.push('\n');
    }
    s.into_bytes()
}

/// A JSON or YAML document of about `size` bytes.
pub fn config_file(rng: &mut Rng, yaml: bool, size: usize) -> Vec<u8> {
    let mut s = String::with_capacity(size + 128);
    if !yaml {
        s.push_str("[\n");
    }
    let mut first = true;
    while s.len() < size {
        let (k1, k2, k3) = (ident(rng), ident(rng), ident(rng));
        let (n, b) = (rng.below(100_000), rng.chance(0.5));
        if yaml {
            s.push_str(&format!("- {k1}: {n}\n  {k2}: {b}\n  {k3}: \"{}-{}\"\n", rng.pick(WORDS), rng.below(1000)));
        } else {
            if !first {
                s.push_str(",\n");
            }
            s.push_str(&format!(
                "  {{\"{k1}\": {n}, \"{k2}\": {b}, \"{k3}\": \"{}-{}\"}}",
                rng.pick(WORDS),
                rng.below(1000)
            ));
        }
        first = false;
    }
    if !yaml {
        s.push_str("\n]\n");
    }
    s.into_bytes()
}

/// `size` incompressible bytes.
pub fn binary_file(rng: &mut Rng, size: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(size + 8);
    while v.len() < size {
        v.extend_from_slice(&rng.next().to_le_bytes());
    }
    v.truncate(size);
    v
}

/// Edit a text file in place, as a developer would: 1–3 hunks, each
/// replacing, inserting or deleting a few lines. `needle`, when given, is
/// planted in one inserted line (for `log -S`).
pub fn edit_text(rng: &mut Rng, data: &[u8], ext: &str, needle: Option<&str>) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if lines.is_empty() {
        lines.push(String::new());
    }
    let hunks = rng.range(1, 3);
    for h in 0..hunks {
        let at = rng.below(lines.len());
        let del = rng.below(4).min(lines.len() - at);
        let ins = match rng.below(3) {
            0 => del,
            1 => del + rng.range(1, 3),
            _ => del.saturating_sub(1),
        };
        let mut new: Vec<String> = (0..ins)
            .map(|_| {
                if ext == "json" || ext == "yaml" {
                    format!("  \"{}\": {}", ident(rng), rng.below(100_000))
                } else {
                    let indent = rng.below(3);
                    source_line(rng, ext, indent)
                }
            })
            .collect();
        if h == 0 {
            if let Some(n) = needle {
                new.push(format!("// {n}"));
            }
        }
        lines.splice(at..at + del, new);
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_bytes() {
        let a = source_file(&mut Rng::fork(7, 3), "rs", 10_000);
        let b = source_file(&mut Rng::fork(7, 3), "rs", 10_000);
        assert_eq!(a, b);
        let c = source_file(&mut Rng::fork(8, 3), "rs", 10_000);
        assert_ne!(a, c);
        let e1 = edit_text(&mut Rng::new(1), &a, "rs", Some("NEEDLE"));
        let e2 = edit_text(&mut Rng::new(1), &a, "rs", Some("NEEDLE"));
        assert_eq!(e1, e2);
        assert!(String::from_utf8(e1).unwrap().contains("NEEDLE"));
    }

    #[test]
    fn sizes_are_close_to_the_request() {
        let mut r = Rng::new(1);
        for size in [100, 5_000, 70_000] {
            let s = source_file(&mut r, "py", size).len();
            assert!(s >= size && s < size + 200, "{s} for {size}");
            let j = config_file(&mut r, false, size).len();
            assert!(j >= size && j < size + 200, "{j} for {size}");
        }
        assert_eq!(binary_file(&mut r, 1001).len(), 1001);
    }

    #[test]
    fn log_normal_median_is_about_right() {
        let mut r = Rng::new(42);
        let mut v: Vec<f64> = (0..10_001).map(|_| r.log_normal(1000.0, 1.0)).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let m = v[5000];
        assert!((800.0..1250.0).contains(&m), "median {m}");
    }
}
