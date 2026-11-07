//! `vl secret … --scope S`, the team vault side of `vl run`, and the
//! revocation report of `vl scope revoke` (see `veil_core::team_vault`).

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
};

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use veil_core::{
    keychain::{validate_scope_name, Keychain},
    team_vault::{env_cost, is_execution_variable, is_identifier, RevokeReport, TeamVault},
    VPath,
};

use crate::{
    api,
    ctx::Ctx,
    render::{dim, fmt_time, safe, warn},
};

/// Warnings about records that do not count (once per reason).
pub(crate) fn ignored_warnings(scope: &str, vault: &TeamVault) -> Vec<String> {
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for i in &vault.ignored {
        *by_reason.entry(i.reason.describe()).or_default() += 1;
    }
    by_reason
        .into_iter()
        .map(|(why, n)| format!("team vault of scope {scope}: ignored {n} record(s): {}", safe(&why)))
        .collect()
}

fn warn_ignored(scope: &str, vault: &TeamVault) {
    for w in ignored_warnings(scope, vault) {
        warn(&w);
    }
}

pub(crate) fn check_scope(keys: &Keychain, scope: &str) -> Result<()> {
    validate_scope_name(scope)?;
    if keys.load_ring(scope)?.is_none() {
        bail!("there is no scope '{scope}' in this repository (create it with `vl scope create {scope}`)");
    }
    Ok(())
}

pub fn set(ctx: &mut Ctx, scope: &str, name: &str, value: &str) -> Result<()> {
    check_scope(ctx.repo.keys(), scope)?;
    let out = ctx.repo.keys().team_secret_write(scope, name, Some(value))?;
    for n in &out.notes {
        warn(&safe(n));
    }
    if is_execution_variable(name) {
        warn(&format!(
            "`vl run` never sets {name} from a team vault: it decides what a command runs or loads, so any member \
             could take over teammates' commands with it. Members who need it copy it into their local vault \
             (`vl secret get --scope {scope} {name} | vl secret set {name}`)"
        ));
    }
    let how = match out.previous.as_ref().filter(|p| p.value.is_some()) {
        Some(p) => format!(
            "the team vault is not part of the operation log, and the previous value of {name} (set by {}) was \
             replaced; set it again with `vl secret set --scope {scope} {name}`. Teammates who pulled it since \
             have the new value",
            safe(&p.signer_name)
        ),
        None => format!(
            "the team vault is not part of the operation log; delete the secret with `vl secret rm --scope {scope} \
             {name}`. Teammates who pulled it since have seen the value: rotate it if that matters"
        ),
    };
    ctx.repo
        .record_outside_view(format!("store secret {name} in the team vault of scope {scope}"), how)?;
    println!("Stored secret {name} in the team vault of scope {scope}; push to share it with its members");
    Ok(())
}

pub fn get(ctx: &Ctx, scope: &str, name: &str) -> Result<()> {
    check_scope(ctx.repo.keys(), scope)?;
    let vault = ctx.repo.keys().team_vault(scope)?;
    warn_ignored(scope, &vault);
    let e = vault
        .get(name)
        .ok_or_else(|| anyhow!("no secret named '{name}' in the team vault of scope '{scope}'"))?;
    println!("{}", e.value.as_deref().unwrap_or_default());
    Ok(())
}

/// `vl secret list --scope S [--exposed-to M] [--json]`.
pub fn list(ctx: &Ctx, scope: &str, exposed_to: Option<&str>, json: bool) -> Result<()> {
    let doc = api::team_secret_list(&ctx.repo, scope, exposed_to)?;
    for w in &doc.warnings {
        warn(w);
    }
    if json {
        return api::emit_json(&doc);
    }
    if let Some(who) = &doc.exposed_to {
        for e in &doc.secrets {
            println!("{}", e.name);
        }
        eprintln!(
            "{}",
            dim(&format!(
                "{} secret(s) of scope {scope} {} readable by {} ({}){}",
                doc.secrets.len(),
                if who.current { "are" } else { "were" },
                safe(&who.name),
                who.member_id,
                if doc.secrets.is_empty() || who.current {
                    String::new()
                } else {
                    ": rotate them at their source, then set the new values".into()
                }
            ))
        );
        return Ok(());
    }
    for e in &doc.secrets {
        let Some(t) = &e.team else { continue };
        let stale = if t.stale_generation {
            "; sealed under an old key generation after a revocation, set it again"
        } else {
            ""
        };
        println!(
            "{}  {}",
            e.name,
            dim(&format!(
                "set by {} {} (key generation {}{stale})",
                safe(&t.set_by),
                fmt_time(t.timestamp_ms),
                t.generation
            ))
        );
    }
    Ok(())
}

pub fn rm(ctx: &mut Ctx, scope: &str, name: &str) -> Result<()> {
    check_scope(ctx.repo.keys(), scope)?;
    let out = ctx.repo.keys().team_secret_write(scope, name, None)?;
    for n in &out.notes {
        warn(&safe(n));
    }
    ctx.repo.record_outside_view(
        format!("remove secret {name} from the team vault of scope {scope}"),
        format!(
            "the team vault is not part of the operation log; set it again with `vl secret set --scope {scope} {name}`"
        ),
    )?;
    println!("Removed secret {name} from the team vault of scope {scope}; push to share the deletion");
    Ok(())
}

// ---- vl run ------------------------------------------------------------------

/// Where `vl run --remember` keeps this device's default scopes (never
/// synced).
const RUN_SCOPES: &str = ".veil/local/run-scopes.json";

#[derive(Serialize, Deserialize)]
struct RunScopes {
    scopes: Vec<String>,
}

fn run_scopes_path() -> VPath {
    VPath::new(RUN_SCOPES).expect("valid path")
}

/// The scopes `vl run` loads by default on this device; `None` if none were
/// chosen yet.
fn remembered(ctx: &Ctx) -> Result<Option<Vec<String>>> {
    let Some(raw) = ctx.repo.backend().read_opt(&run_scopes_path())? else {
        return Ok(None);
    };
    let r: RunScopes = serde_json::from_slice(&raw).map_err(|e| anyhow!("{RUN_SCOPES} cannot be parsed: {e}"))?;
    Ok(Some(r.scopes))
}

/// `vl run --remember`: make `scopes` (none: only the local vault) this
/// device's default.
pub fn remember(ctx: &Ctx, scopes: &[String]) -> Result<()> {
    for s in scopes {
        check_scope(ctx.repo.keys(), s)?;
    }
    let mut scopes = scopes.to_vec();
    scopes.sort();
    scopes.dedup();
    let raw = serde_json::to_vec(&RunScopes { scopes: scopes.clone() })?;
    ctx.repo.backend().write(&run_scopes_path(), &raw)?;
    if scopes.is_empty() {
        eprintln!("vl run now loads no team vault by default on this device (only the local vault)");
    } else {
        eprintln!(
            "vl run now loads the team vault of {} by default on this device",
            scopes.iter().map(|s| format!("scope {s}")).collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

/// What one loaded scope adds to `vl run`'s environment.
pub struct ScopeSize {
    pub scope: String,
    pub bytes: usize,
    /// Entries set, largest first: (name, bytes).
    pub entries: Vec<(String, usize)>,
}

/// The team-vault variables `vl run` sets.
#[derive(Default)]
pub struct RunEnv {
    pub vars: BTreeMap<String, String>,
    pub sizes: Vec<ScopeSize>,
}

/// The team-vault variables `vl run` sets: those of `scopes`, or by
/// default of the scopes `vl run --remember` chose on this device (none
/// until then, BUG-520: a member of any loaded scope chooses variables that
/// a command sees next to every other loaded scope's secrets). A name two
/// scopes set to different values is an error, unless `overridden` (the
/// local vault) has it. Names that are not shell identifiers, or that
/// decide what a command runs or loads ([`is_execution_variable`]), are
/// never set from a team vault; they are skipped with a warning.
pub fn run_env(
    ctx: &Ctx,
    scopes: &[String],
    local_only: bool,
    overridden: &BTreeMap<String, String>,
) -> Result<RunEnv> {
    let keys = ctx.repo.keys();
    if local_only {
        return Ok(RunEnv::default());
    }
    let explicit = !scopes.is_empty();
    let chosen: Vec<String> = if explicit {
        for s in scopes {
            check_scope(keys, s)?;
        }
        scopes.to_vec()
    } else {
        match remembered(ctx)? {
            Some(list) => list,
            None => {
                let with_vault = keys.team_vault_scopes()?;
                let available: Vec<String> = keys
                    .member_scopes()?
                    .into_iter()
                    .filter(|s| with_vault.contains(s))
                    .collect();
                if !available.is_empty() {
                    let first = &available[0];
                    eprintln!(
                        "{}",
                        dim(&format!(
                            "vl run: no team vault loaded ({} {} secrets). Load one with `vl run --scope {first} -- …`, \
                             or make it this device's default with `vl run --scope {first} --remember`",
                            available.iter().map(|s| format!("scope {s}")).collect::<Vec<_>>().join(", "),
                            if available.len() == 1 { "holds" } else { "hold" }
                        ))
                    );
                }
                vec![]
            }
        }
    };
    let mut env: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut sizes = Vec::new();
    for scope in &chosen {
        let vault = match keys.team_vault(scope) {
            Ok(v) => v,
            Err(e) if !explicit => {
                warn(&format!("team vault of scope {scope} not loaded: {e}"));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        warn_ignored(scope, &vault);
        let mut skipped_exec = BTreeSet::new();
        let mut skipped_names = BTreeSet::new();
        let mut stale = BTreeSet::new();
        let mut size = ScopeSize {
            scope: scope.clone(),
            bytes: 0,
            entries: vec![],
        };
        for e in vault.live() {
            if overridden.contains_key(&e.name) {
                continue;
            }
            if !is_identifier(&e.name) {
                skipped_names.insert(e.name.clone());
                continue;
            }
            if is_execution_variable(&e.name) {
                skipped_exec.insert(e.name.clone());
                continue;
            }
            if e.stale_generation {
                stale.insert(e.name.clone());
            }
            let value = e.value.clone().unwrap_or_default();
            match env.get(&e.name) {
                Some((other, v)) if *v != value => bail!(
                    "secret {} is set in the team vaults of scopes '{other}' and '{scope}' with different values; \
                     choose with `vl run --scope <scope>`, or set it in the local vault to override both",
                    e.name
                ),
                Some(_) => {}
                None => {
                    let cost = env_cost(&e.name, &value);
                    size.bytes += cost;
                    size.entries.push((e.name.clone(), cost));
                    env.insert(e.name.clone(), (scope.clone(), value));
                }
            }
        }
        if !skipped_exec.is_empty() {
            warn(&format!(
                "team vault of scope {scope}: not setting {}: variables that decide what a command runs or loads never \
                 come from a team vault, since any member of the scope could set them. If you trust a value, copy it \
                 into your local vault (`vl secret get --scope {scope} NAME | vl secret set NAME`)",
                skipped_exec.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        if !skipped_names.is_empty() {
            warn(&format!(
                "team vault of scope {scope}: not setting {}: not shell identifiers (letters, digits and '_')",
                safe(&skipped_names.into_iter().collect::<Vec<_>>().join(", "))
            ));
        }
        if !stale.is_empty() {
            warn(&format!(
                "team vault of scope {scope}: {} sealed under an old key generation after a revocation, so the \
                 revoked member can read it; set it again with `vl secret set --scope {scope} NAME`, and rotate it",
                stale.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        size.entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        sizes.push(size);
    }
    Ok(RunEnv {
        vars: env.into_iter().map(|(k, (_, v))| (k, v)).collect(),
        sizes,
    })
}

/// What `execve` will be handed: arguments and environment, as it counts
/// them against `ARG_MAX` (each string, its NUL and its pointer).
pub fn exec_size(command: &[String], env: &BTreeMap<OsString, OsString>) -> usize {
    let ptr = std::mem::size_of::<usize>();
    let args: usize = command.iter().map(|a| a.len() + 1 + ptr).sum();
    let vars: usize = env.iter().map(|(k, v)| k.len() + 1 + v.len() + 1 + ptr).sum();
    args + vars + 2 * ptr
}

/// This system's `ARG_MAX` (arguments and environment together).
pub fn arg_max() -> usize {
    // SAFETY: sysconf has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
    if n > 0 {
        n as usize
    } else {
        // POSIX's minimum `_POSIX_ARG_MAX`.
        4096
    }
}

/// BUG-523: the error when the command's arguments and environment are
/// more than the system takes, naming what the team vaults add.
pub fn too_big(total: usize, limit: usize, team: &RunEnv) -> anyhow::Error {
    let mut sizes: Vec<&ScopeSize> = team.sizes.iter().filter(|s| s.bytes > 0).collect();
    sizes.sort_by_key(|s| std::cmp::Reverse(s.bytes));
    let parts: Vec<String> = sizes
        .iter()
        .map(|s| {
            let largest: Vec<&str> = s.entries.iter().take(3).map(|(n, _)| n.as_str()).collect();
            format!(
                "scope '{}' adds {} KiB in {} entries (largest: {})",
                s.scope,
                s.bytes.div_ceil(1024),
                s.entries.len(),
                largest.join(", ")
            )
        })
        .collect();
    let team_part = if parts.is_empty() {
        "No team vault adds to it.".to_string()
    } else {
        format!(
            "From team vaults: {}. Load fewer scopes with `vl run --scope SCOPE`, or none with `--local-only`.",
            parts.join("; ")
        )
    };
    anyhow!(
        "the command's arguments and environment would take {} KiB, more than this system passes to a program ({} KiB, \
         ARG_MAX). {team_part}",
        total.div_ceil(1024),
        limit / 1024
    )
}

/// What `vl scope revoke` prints about the team vault.
pub fn print_revoke_report(scope: &str, report: &RevokeReport) {
    if let Some(w) = &report.warning {
        warn(w);
    }
    if !report.exposed.is_empty() {
        println!(
            "Team vault of scope {scope}: the revoked identity could read {} secret(s). Rotate each at its source,\n\
             then store the new value with `vl secret set --scope {scope} <name>`:",
            report.exposed.len()
        );
        for n in &report.exposed {
            println!("  {n}");
        }
        println!(
            "{}",
            dim(&format!("(list them again later with `vl secret list --scope {scope} --exposed-to <their key>`)"))
        );
    }
    if !report.adopted.is_empty() {
        println!(
            "Their writes no longer count, so you re-signed the {} secret(s) they last set (still to rotate): {}",
            report.adopted.len(),
            report.adopted.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_big_names_the_scopes_and_their_largest_entries() {
        let team = RunEnv {
            vars: BTreeMap::new(),
            sizes: vec![
                ScopeSize {
                    scope: "small".into(),
                    bytes: 100,
                    entries: vec![("A".into(), 100)],
                },
                ScopeSize {
                    scope: "team".into(),
                    bytes: 2_560_000,
                    entries: (0..40).map(|i| (format!("BLOB_{i:02}"), 64_000)).collect(),
                },
            ],
        };
        let e = too_big(2_600_000, 2 * 1024 * 1024, &team).to_string();
        assert!(e.contains("scope 'team' adds 2500 KiB in 40 entries (largest: BLOB_00, BLOB_01, BLOB_02)"), "{e}");
        assert!(e.find("'team'") < e.find("'small'"), "largest scope first: {e}");
        assert!(e.contains("--scope") && e.contains("--local-only"), "{e}");
    }

    #[test]
    fn exec_size_counts_strings_nuls_and_pointers() {
        let p = std::mem::size_of::<usize>();
        let env: BTreeMap<OsString, OsString> = [("A".into(), "bc".into())].into_iter().collect();
        assert_eq!(exec_size(&["ls".into()], &env), (3 + p) + (5 + p) + 2 * p);
        assert!(arg_max() >= 4096);
    }
}
