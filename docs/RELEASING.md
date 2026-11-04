# Releasing Veil

A release is a Git tag. Pushing `v1.2.3` builds `vl` for every supported
platform, creates the GitHub Release and publishes the Homebrew formula.
Everything below the tag is automated. This document covers what has to be
right *before* the tag, and how to check the result.

## What a release contains

| Asset | Contents |
|---|---|
| `vl-<target>.tar.xz` | `vl`, `README.md`, `completions/` (`vl.bash`, `_vl`, `vl.fish`) and `man/` (`vl.1`, `vl-<command>.1`, …) |
| `vl-<target>.tar.xz.sha256` | its SHA-256 (`sha256sum -c` / `shasum -a 256 -c`) |
| `sha256.sum` | every checksum in one file |
| `vl-installer.sh` | shell installer: picks the target, verifies the checksum, installs into `$CARGO_HOME/bin` |
| `vl.rb` | the Homebrew formula (also pushed to the tap) |
| `source.tar.gz` | the source at the tag |

Targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (static
binaries, so they run on any Linux distribution), `x86_64-apple-darwin` and
`aarch64-apple-darwin`. Each one is built natively on its own GitHub runner.

## How it is wired

| File | Role |
|---|---|
| `dist-workspace.toml` | [dist](https://github.com/axodotdev/cargo-dist) configuration: targets, installers, checksums |
| `crates/vl/Cargo.toml` `[package.metadata.dist]` | puts the generated completions and man pages in every archive |
| `.github/build-setup.yml` | steps dist runs before each build: generate completions and man pages, set the musl C compiler on aarch64 |
| `.github/workflows/release.yml` | **generated** by `dist generate`; never edit it by hand |
| `.github/workflows/publish-homebrew.yml` | after a successful Release: renders and publishes `vl.rb` |
| `packaging/homebrew/vl.rb.in`, `render-formula.sh` | the formula template and its renderer |
| `Cargo.toml` `[profile.dist]` | the profile release binaries are built with (same as `release`) |

`release.yml` also runs on pull requests, where it only runs `dist plan`.
CI's `packaging` job runs `dist plan` on every push too, which fails if
`release.yml` no longer matches `dist-workspace.toml` and
`.github/build-setup.yml`. After changing either, install dist (the version
in `cargo-dist-version`) and run `dist generate`.

Homebrew is published by its own workflow, not by dist's `homebrew`
installer: dist's formula leaves completions and man pages in `pkgshare`
instead of installing them, and dist 0.34 renders custom publish jobs with
an invalid `uses: $/...` path.

## One-time setup

1. **GitHub repository.** Push to the repository named by `repository` in
   the root `Cargo.toml` (`veil-vcs/veil` at present). If you use another
   name, change `repository` and `homepage` there, plus the URLs in
   `README.md` (Install), then run `dist generate`. The installer script and
   the formula take their download URLs from it.
2. **Actions.** The workflows request the `GITHUB_TOKEN` permissions they
   need (`contents: write` to create the Release and upload assets), so
   nothing needs changing unless an organisation policy caps the token at
   read-only. `publish-homebrew.yml` is triggered by `workflow_run`, which
   GitHub only honours for workflow files on the default branch: merge
   `.github/` to `main` before the first tag.
3. **Homebrew tap.** Create a public repository `<owner>/homebrew-tap` with
   an empty `Formula/` directory (or a README). Users then run
   `brew install <owner>/tap/vl`. To use another tap, set the repository
   **variable** `HOMEBREW_TAP` to its `owner/repo`.
4. **Tap token.** Create a fine-grained personal access token with access to
   the tap repository only and **Contents: Read and write**. Store it as the
   repository **secret** `HOMEBREW_TAP_TOKEN`. Without it, releases still
   attach `vl.rb` and the workflow prints a warning instead of pushing.
5. **Runners.** The aarch64 Linux build and CI's `musl` job use the
   `ubuntu-22.04-arm` / `ubuntu-24.04-arm` runners. They are free for public
   repositories. For a private repository, check that your plan includes
   them, or drop `aarch64-unknown-linux-musl` from `targets` (and from the
   `musl` job in `ci.yml`).

## Before the tag

### 1. Everything is green

* CI on `main` (Linux and macOS: build, tests, doc tests, clippy, musl,
  packaging).
* The latest **Nightly** run (deep property tests). Run it by hand from the
  Actions tab if the last one is old.

### 2. Bump the version

The version lives in one place, `[workspace.package] version` in the root
`Cargo.toml`; both crates inherit it.

```sh
$EDITOR Cargo.toml              # version = "1.2.3"
cargo update --workspace        # records it in Cargo.lock
cargo test -p vl --test version # `vl --version` reports it
```

Use SemVer. A pre-release suffix (`1.2.3-rc.1`) makes the GitHub Release a
pre-release, and its formula is attached to the release but not pushed to
the tap. The tag must match the version exactly (`v1.2.3` for `1.2.3`), or
`dist` refuses to build.

### 3. The repository format

`REPO_FORMAT_VERSION` (`crates/veil-core/src/repo.rs`) is the format of
everything a `vl` writes under `.veil/`: objects, trees, packs, key rings,
the operation log, `repo.json`. A `vl` refuses repositories newer than its
own format, so getting this wrong locks users out or corrupts repositories.
For every release:

1. List what changed in the on-disk code since the last release:

   ```sh
   git diff v1.2.2 --stat -- crates/veil-core/src/{object,tree,store,pack,repo,keychain,oplog,id}.rs docs/FORMAT.md
   ```

2. If any byte that is written or read changed meaning (a new field,
   object kind, encoding or file), the format changed:
   * bump `REPO_FORMAT_VERSION`;
   * update the two literals in `crates/vl/src/cli.rs` (`VERSION` and
     `LONG_VERSION`). `crates/vl/tests/version.rs` fails until they match;
   * make sure `vl upgrade` migrates every older format to the new one, and
     that it is tested;
   * update **`docs/FORMAT.md`**: the version number, the change, and how
     `vl upgrade` migrates.
3. If the code changed but you are sure the format did not (for example a
   refactor), say so in the release notes. If `docs/FORMAT.md` changed, the
   format version should normally have changed too.
4. Check: `vl --version` on the release build reports the new
   `repository format`, and `vl doctor` in a repository created by the
   previous release shows its format as older (or upgrade it with
   `vl upgrade`).

### 4. Release notes

dist uses the section of `CHANGELOG.md` (or `RELEASES.md`) whose heading
matches the version (`## 1.2.3`) as the Release body. Without one the
body only lists the assets. Mention format changes and `vl upgrade` steps
first.

### 5. Optional dry run

```sh
dist plan --tag v1.2.3      # what would be built; fails on config problems
```

A pull request also runs `dist plan` (the `plan` job of `release.yml`).
To build an archive locally (Linux needs `musl-tools` and
`rustup target add x86_64-unknown-linux-musl`), generate the extras first,
as `.github/build-setup.yml` does, then:

```sh
dist build --artifacts=local --target x86_64-unknown-linux-musl --tag v1.2.3
ls target/distrib/
```

## Cut the release

```sh
git switch main && git pull --ff-only
# version bump, format checks and CHANGELOG committed:
git commit -am "Release 1.2.3"
git tag -a v1.2.3 -m "vl 1.2.3"     # or -s to sign it
git push origin main v1.2.3
```

The **Release** workflow then runs:

1. `plan`: `dist plan` for the tag;
2. `build-local-artifacts`, one job per target: generates completions and man
   pages, builds `vl` with the `dist` profile, packs the archive and its
   checksum;
3. `build-global-artifacts`: the installer script, `sha256.sum`, the source
   archive;
4. `host`: creates the GitHub Release and uploads everything;
5. `announce`.

When it succeeds, **Publish Homebrew formula** renders `vl.rb` from the
release's checksums, attaches it to the Release and pushes it to the tap.

## Check the release

```sh
# Installer (on a Linux and a macOS machine)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/veil-vcs/veil/releases/download/v1.2.3/vl-installer.sh | sh
vl --version            # 1.2.3, the tag's commit, the repository format, the target
vl doctor

# Homebrew
brew update && brew install veil-vcs/tap/vl    # or brew upgrade vl
brew test vl
man vl-commit; vl <TAB>

# Checksums
gh release download v1.2.3 -p 'vl-x86_64-unknown-linux-musl.tar.xz*'
sha256sum -c vl-x86_64-unknown-linux-musl.tar.xz.sha256
```

## When something fails

* **A build job fails:** nothing has been published yet; the Release is only
  created by `host`, after all builds. Fix the problem on `main`, then move
  the tag: `git tag -d v1.2.3 && git push --delete origin v1.2.3`, tag again
  and push.
* **The Release exists but is wrong:** do not reuse the version, as users may
  already have it. Delete or edit the Release if needed and publish `1.2.4`.
* **Homebrew publishing failed or was skipped** (for example the token was
  added later): Actions → Publish Homebrew formula → Run workflow, with the
  tag.

## Maintenance

* **Updating dist:** install the new version, set `cargo-dist-version` in
  `dist-workspace.toml`, run `dist generate`, and update the dist version
  in the `packaging` job of `ci.yml`. Read the generated diff. If a new
  dist installs completions and man pages in its Homebrew formula and
  renders custom jobs correctly, `publish-homebrew.yml` could become a dist
  `publish-jobs` entry.
* **Actions** are pinned to release tags (`actions/checkout@v7.0.1`,
  `Swatinem/rust-cache@v2.9.3`, …) in `ci.yml`, `nightly.yml` and
  `publish-homebrew.yml`. `release.yml` uses the versions dist chooses.
  `actionlint` runs in CI with its own pinned version and checksum
  (configuration: `.github/actionlint.yaml`).
