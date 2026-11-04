//! Remote URLs for the SFTP backend.
//!
//! * `ssh://[user@]host[:port]/absolute/path` (also `sftp://`). A path
//!   starting with `/~/` is relative to the remote home directory.
//! * scp-style `[user@]host:path`: relative to the home directory unless
//!   `path` starts with `/`. IPv6 hosts go in brackets: `[::1]:repo`.
//!
//! As with Git, a string is scp-style only if a `:` comes before any `/`,
//! so `./odd:name` and `/tmp/a:b` are local paths.

use std::fmt;

use crate::error::{Result, VeilError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshUrl {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    /// Path on the server: absolute, or relative to the login directory
    /// (empty means the login directory itself).
    pub path: String,
}

fn bad(s: &str, why: &str) -> VeilError {
    VeilError::InvalidPath(format!("remote URL '{s}': {why}"))
}

/// `host` and `user` reach `ssh`'s command line. `--` already ends option
/// parsing, but a leading `-` is never a valid name, so refuse it anyway.
fn check_name(s: &str, what: &str, v: &str) -> Result<()> {
    if v.is_empty() {
        return Err(bad(s, &format!("empty {what}")));
    }
    if v.starts_with('-') || v.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad(s, &format!("invalid {what} '{v}'")));
    }
    Ok(())
}

fn split_user(s: &str, authority: &str) -> Result<(Option<String>, String)> {
    match authority.rsplit_once('@') {
        Some((u, h)) => {
            check_name(s, "user", u)?;
            Ok((Some(u.to_string()), h.to_string()))
        }
        None => Ok((None, authority.to_string())),
    }
}

fn normalise_path(p: &str) -> String {
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() && p.starts_with('/') {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

impl SshUrl {
    /// `None` if `s` is not an SSH remote at all (a local path); `Some(Err)`
    /// if it looks like one but is malformed.
    pub fn parse(s: &str) -> Option<Result<SshUrl>> {
        if let Some(rest) = s.strip_prefix("ssh://").or_else(|| s.strip_prefix("sftp://")) {
            return Some(Self::parse_url(s, rest));
        }
        if s.contains("://") {
            return Some(Err(bad(s, "unsupported scheme (use ssh://, sftp:// or host:path)")));
        }
        // scp-style: a ':' before any '/', outside IPv6 brackets.
        let colon = if s.starts_with('[') || s.contains("@[") {
            let close = s.find(']')?;
            close + s[close..].find(':')?
        } else {
            s.find(':')?
        };
        let (authority, path) = (&s[..colon], &s[colon + 1..]);
        if authority.is_empty() || authority.contains('/') {
            return None;
        }
        Some((|| {
            let (user, host) = split_user(s, authority)?;
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .map(str::to_string)
                .unwrap_or(host);
            check_name(s, "host", &host)?;
            Ok(SshUrl {
                user,
                host,
                port: None,
                path: normalise_path(path),
            })
        })())
    }

    fn parse_url(s: &str, rest: &str) -> Result<SshUrl> {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (user, hostport) = split_user(s, authority)?;
        let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
            let (h, after) = h.split_once(']').ok_or_else(|| bad(s, "unterminated '['"))?;
            match after {
                "" => (h.to_string(), None),
                p => (h.to_string(), Some(p.strip_prefix(':').ok_or_else(|| bad(s, "junk after ']'"))?)),
            }
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (hostport.clone(), None),
            }
        };
        check_name(s, "host", &host)?;
        let port = match port {
            None | Some("") => None,
            Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| bad(s, "invalid port"))?),
        };
        let path = if path == "/~" {
            String::new()
        } else if let Some(rel) = path.strip_prefix("/~/") {
            rel.to_string()
        } else {
            path.to_string()
        };
        Ok(SshUrl {
            user,
            host,
            port,
            path: normalise_path(&path),
        })
    }

    /// Arguments for `ssh` that open the `sftp` subsystem on this host, in
    /// the form `sftp(1)` itself uses. Everything else (keys, agent,
    /// known_hosts, ProxyJump, ControlMaster…) comes from the user's
    /// `~/.ssh/config`.
    pub fn ssh_args(&self) -> Vec<String> {
        let mut a: Vec<String> = [
            "-oForwardX11=no",
            "-oForwardAgent=no",
            "-oPermitLocalCommand=no",
            "-oClearAllForwardings=yes",
        ]
        .map(String::from)
        .to_vec();
        if let Some(p) = self.port {
            a.push("-p".into());
            a.push(p.to_string());
        }
        if let Some(u) = &self.user {
            a.push("-l".into());
            a.push(u.clone());
        }
        a.push("-s".into());
        a.push("--".into());
        a.push(self.host.clone());
        a.push("sftp".into());
        a
    }

    /// The last path component, for naming a clone's directory.
    pub fn last_component(&self) -> Option<&str> {
        self.path.rsplit('/').next().filter(|c| !c.is_empty() && *c != "." && *c != "..")
    }
}

impl fmt::Display for SshUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ssh://")?;
        if let Some(u) = &self.user {
            write!(f, "{u}@")?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        if self.path.starts_with('/') {
            write!(f, "{}", self.path)
        } else if self.path.is_empty() {
            write!(f, "/~")
        } else {
            write!(f, "/~/{}", self.path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> SshUrl {
        SshUrl::parse(s).expect("is an ssh url").expect("valid")
    }

    #[test]
    fn ssh_urls() {
        assert_eq!(
            p("ssh://alice@example.com:2222/srv/repo/"),
            SshUrl {
                user: Some("alice".into()),
                host: "example.com".into(),
                port: Some(2222),
                path: "/srv/repo".into()
            }
        );
        assert_eq!(p("ssh://h/~/code/x").path, "code/x");
        assert_eq!(p("sftp://h").path, "");
        assert_eq!(p("ssh://[::1]:22/r").host, "::1");
        assert_eq!(p("ssh://[::1]/r").port, None);
        assert!(SshUrl::parse("ssh://h:99999/r").unwrap().is_err());
        assert!(SshUrl::parse("ssh://-oProxyCommand=x/r").unwrap().is_err());
        assert!(SshUrl::parse("http://h/r").unwrap().is_err());
    }

    #[test]
    fn scp_style() {
        let u = p("bob@host:repos/proj");
        assert_eq!((u.user.as_deref(), u.host.as_str(), u.path.as_str()), (Some("bob"), "host", "repos/proj"));
        assert_eq!(p("host:/abs/p").path, "/abs/p");
        assert_eq!(p("host:").path, "");
        assert_eq!(p("[fe80::1]:r").host, "fe80::1");
        assert_eq!(p("u@[fe80::1]:r").user.as_deref(), Some("u"));
        assert!(SshUrl::parse("-oProxyCommand=evil:x").unwrap().is_err());
        assert_eq!(p("host:repos/proj").last_component(), Some("proj"));
        assert_eq!(p("host:").last_component(), None);
    }

    #[test]
    fn local_paths_are_not_urls() {
        for s in ["/tmp/a:b", "./odd:name", "../x", "plain", "dir/sub:x", ":x"] {
            assert!(SshUrl::parse(s).is_none(), "{s}");
        }
    }

    #[test]
    fn display_round_trips() {
        for s in ["ssh://a@h:2/x/y", "ssh://h/~/rel", "ssh://[::1]/abs", "ssh://h/~"] {
            assert_eq!(p(&p(s).to_string()), p(s), "{s}");
        }
    }
}
