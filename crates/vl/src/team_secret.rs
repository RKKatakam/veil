//! `vl secret … --scope S`, the team vault side of `vl run`, and the
//! revocation report of `vl scope revoke` (see `veil_core::team_vault`).

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use veil_core::{
    keychain::{validate_scope_name, Keychain},
    team_vault::{RevokeReport, TeamVault},
};

use crate::{
    ctx::Ctx,
    render::{dim, fmt_time, safe, warn},
};

/// Warn about records that do not count (once per reason).
fn warn_ignored(scope: &str, vault: &TeamVault) {
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for i in &vault.ignored {
        *by_reason.entry(i.reason.describe()).or_default() += 1;
    }
    for (why, n) in by_reason {
        warn(&format!("team vault of scope {scope}: ignored {n} record(s): {}", safe(&why)));
    }
}

fn check_scope(keys: &Keychain, scope: &str) -> Result<()> {
    validate_scope_name(scope)?;
    if keys.load_ring(scope)?.is_none() {
        bail!("there is no scope '{scope}' in this repository (create it with `vl scope create {scope}`)");
    }
    Ok(())
}

pub fn set(ctx: &mut Ctx, scope: &str, name: &str, value: &str) -> Result<()> {
    check_scope(ctx.repo.keys(), scope)?;
    let out = ctx.repo.keys().team_secret_write(scope, name, Some(value))?;
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

pub fn list(ctx: &Ctx, scope: &str, exposed_to: Option<&str>) -> Result<()> {
    let keys = ctx.repo.keys();
    check_scope(keys, scope)?;
    if let Some(who) = exposed_to {
        let (id, name, exposed) = keys.team_vault_exposed_to(scope, who)?;
        for e in &exposed {
            println!("{}", e.name);
        }
        let current = keys
            .ring_state(scope)?
            .and_then(|r| r.ok())
            .is_some_and(|st| st.members.contains_key(&id));
        eprintln!(
            "{}",
            dim(&format!(
                "{} secret(s) of scope {scope} {} readable by {} ({id}){}",
                exposed.len(),
                if current { "are" } else { "were" },
                safe(&name),
                if exposed.is_empty() || current {
                    String::new()
                } else {
                    ": rotate them at their source, then set the new values".into()
                }
            ))
        );
        return Ok(());
    }
    let vault = keys.team_vault(scope)?;
    warn_ignored(scope, &vault);
    for e in vault.live() {
        println!(
            "{}  {}",
            e.name,
            dim(&format!(
                "set by {} {} (key generation {})",
                safe(&e.signer_name),
                fmt_time(e.timestamp),
                e.generation
            ))
        );
    }
    Ok(())
}

pub fn rm(ctx: &mut Ctx, scope: &str, name: &str) -> Result<()> {
    check_scope(ctx.repo.keys(), scope)?;
    ctx.repo.keys().team_secret_write(scope, name, None)?;
    ctx.repo.record_outside_view(
        format!("remove secret {name} from the team vault of scope {scope}"),
        format!(
            "the team vault is not part of the operation log; set it again with `vl secret set --scope {scope} {name}`"
        ),
    )?;
    println!("Removed secret {name} from the team vault of scope {scope}; push to share the deletion");
    Ok(())
}

/// The team-vault variables `vl run` sets: those of `scopes` (default:
/// every scope this identity is a member of whose team vault holds
/// something). A name two scopes set to different values is an error,
/// unless `overridden` (the local vault) has it.
pub fn run_env(
    ctx: &Ctx,
    scopes: &[String],
    local_only: bool,
    overridden: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let keys = ctx.repo.keys();
    if local_only {
        return Ok(BTreeMap::new());
    }
    let explicit = !scopes.is_empty();
    let chosen: Vec<String> = if explicit {
        for s in scopes {
            check_scope(keys, s)?;
        }
        scopes.to_vec()
    } else {
        let with_vault = keys.team_vault_scopes()?;
        keys.member_scopes()?
            .into_iter()
            .filter(|s| with_vault.contains(s))
            .collect()
    };
    let mut env: BTreeMap<String, (String, String)> = BTreeMap::new();
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
        for e in vault.live() {
            let value = e.value.clone().unwrap_or_default();
            match env.get(&e.name) {
                Some((other, v)) if *v != value && !overridden.contains_key(&e.name) => bail!(
                    "secret {} is set in the team vaults of scopes '{other}' and '{scope}' with different values; \
                     choose with `vl run --scope <scope>`, or set it in the local vault to override both",
                    e.name
                ),
                Some(_) => {}
                None => {
                    env.insert(e.name.clone(), (scope.clone(), value));
                }
            }
        }
    }
    Ok(env.into_iter().map(|(k, (_, v))| (k, v)).collect())
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
