# Security policy

Veil protects secrets: cloaked and isolated files, embargoed fixes, team
keys. A flaw in that protection can expose someone's data, so please report
it privately, not in a public issue, pull request or discussion.

## Reporting a vulnerability

> **TODO (maintainer): fill in before the first public release.**
> Replace the placeholder below with a real, monitored private contact,
> and remove this note. Until then there is no private channel.

* **Email:** `SECURITY-CONTACT-PLACEHOLDER@example.invalid` *(placeholder:
  not a real address)*
* **GitHub:** once the repository has
  [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  enabled, use **Security → Report a vulnerability** on the repository page.

Please include:

* the `vl --version` output (version, commit, repository format, target);
* what an attacker needs: a remote they control, a Git branch they can push,
  a team membership, a revoked key, local access, …;
* what they gain, and the steps or a test that shows it;
* whether the issue is already public anywhere.

You should get an acknowledgement within 7 days. We will agree on a
disclosure date with you, normally within 90 days of the report, and credit
you in the release notes unless you prefer not to be named.

## Supported versions

Veil is not yet at 1.0. Until it is, only the **latest release** gets
security fixes. From 1.0 on, the latest minor release of the current major
version is supported. Fixes are not backported to older releases; upgrade
with `vl upgrade` if the repository format changed.

| Version | Supported |
|---|---|
| latest release | yes |
| anything older | no |

## What counts as a vulnerability

Anything that breaks a guarantee listed under **Protected against** in the
[threat model](docs/ARCHITECTURE.md#threat-model), for example:

* cloaked, isolated or embargoed content, names or keys reaching someone
  outside their scope (a public remote, a Git remote, a non-member);
* a revoked member reading content sealed after the revocation;
* forged or tampered rings, embargo records or snapshot signatures being
  accepted;
* a hostile remote, Git repository or SFTP server writing outside the
  repository, running code, or making `vl` hang or exhaust memory;
* a weakness in a cryptographic construction (see
  [docs/CRYPTO.md](docs/CRYPTO.md) for every construction, its standard and
  its intended guarantees);
* a compromise of the release artefacts or of the build and release
  workflows (`docs/RELEASING.md`).

The threat model also lists what Veil does **not** protect against yet
(for example the visibility of cloaked file names and sizes, and
forward-only revocation). Reports in those areas are welcome, but they are
known limitations, not vulnerabilities.

## Verifying a release

Every release archive has a `.sha256` file, and `sha256.sum` lists them
all. The shell installer and the Homebrew formula check these checksums.
See `docs/RELEASING.md`, "Check the release".
