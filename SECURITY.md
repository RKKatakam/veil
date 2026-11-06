# Security policy

Veil protects private folders, secrets, embargoed fixes and personal keys
(who can see what: [docs/VISIBILITY.md](docs/VISIBILITY.md)). A flaw in that protection can expose someone's data, so please report
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
* what an attacker needs: a remote or server they control, access to some
  folders, a removed membership, local access, …;
* what they gain, and the steps or a test that shows it;
* whether the issue is already public anywhere.

You should get an acknowledgement within 7 days. We will agree on a
disclosure date with you, normally within 90 days of the report, and credit
you in the release notes unless you prefer not to be named.

## Supported versions

Until the first stable release, only the **latest release** gets security
fixes. From then on, the latest minor release of the current major version
is supported. Fixes are not backported to older releases; upgrade
with `vl upgrade` if the repository format changed.

| Version | Supported |
|---|---|
| latest release | yes |
| anything older | no |

## What counts as a vulnerability

Anything that breaks a guarantee listed under **Protected against** in the
[threat model](docs/ARCHITECTURE.md#threat-model), for example:

* private, secret or embargoed content, names or keys reaching someone
  without access (a public remote or reader, a person outside the folder's
  groups);
* a secret stored unencrypted, or a personal private key leaving the
  machine;
* a removed member reading secrets written after the removal;
* forged or tampered rings, embargo records or snapshot signatures being
  accepted;
* a hostile remote or server writing outside the repository, running code, or making `vl` hang or exhaust memory;
* a weakness in a cryptographic construction (see
  [docs/CRYPTO.md](docs/CRYPTO.md) for every construction, its standard and
  its intended guarantees);
* a compromise of the release artefacts or of the build and release
  workflows (`docs/RELEASING.md`).

The threat model also lists what Veil does **not** protect against yet
(for example forward-only revocation: a removed member keeps what they
already had). Reports in those areas are welcome, but they are
known limitations, not vulnerabilities.

## Verifying a release

Every release archive has a `.sha256` file, and `sha256.sum` lists them
all. The shell installer and the Homebrew formula check these checksums.
See `docs/RELEASING.md`, "Check the release".
