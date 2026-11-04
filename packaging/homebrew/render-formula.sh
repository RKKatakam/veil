#!/bin/sh
# Render packaging/homebrew/vl.rb.in into a Homebrew formula on stdout.
#
#   render-formula.sh <tag> <artifacts-dir> [<owner/repo>]
#   render-formula.sh --check-tag <tag>
#
# <tag> is the release tag (`v1.0.0`, `v1.0.0-rc.1`); <artifacts-dir> holds
# the `vl-<target>.tar.xz.sha256` files of that release (dist writes them
# next to the archives; `gh release download <tag> -p '*.sha256'` fetches
# them). <owner/repo> defaults to $GITHUB_REPOSITORY, then veil-vcs/veil.
# `--check-tag` only checks the tag (exit status 0 or 1).
#
# Every value pasted into the formula comes from outside (a tag anyone with
# push access can name, a downloaded file), and the formula is Ruby that
# every `brew install` runs. So each value is checked against a strict
# pattern first, and the substitution is a literal string replacement in
# awk, with the values passed through the environment: no value is ever
# part of a sed, awk or Ruby program.
set -eu

usage() {
  echo "usage: $0 <tag> <artifacts-dir> [<owner/repo>] | --check-tag <tag>" >&2
  exit 2
}
check_only=false
if [ "${1-}" = --check-tag ]; then
  [ $# -eq 2 ] || usage
  check_only=true
  shift
  set -- "$1" ""
fi
[ $# -ge 2 ] || usage
tag=$1
dir=$2
repo=${3:-${GITHUB_REPOSITORY:-veil-vcs/veil}}
template=$(dirname "$0")/vl.rb.in
targets="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl"

# `matches <value> <extended regex>`: the whole value matches. The `case`
# rejects newlines (grep matches line by line) and anything outside the
# allowed characters before grep sees the value.
matches() {
  case $1 in
    "" | *[!0-9A-Za-z._/-]*) return 1 ;;
  esac
  printf '%s\n' "$1" | grep -Eqx "$2"
}

# SemVer 2.0: major.minor.patch without leading zeros, with an optional
# pre-release; no build metadata (`+` has no use in a tag). A subset of what
# Cargo and dist accept, and only characters that are inert in a Ruby
# string, a URL and a shell word.
num='(0|[1-9][0-9]*)'
ident='[0-9A-Za-z-]+'
matches "$tag" "v$num\\.$num\\.$num(-$ident(\\.$ident)*)?" || {
  # (Not echoed: it is untrusted, and on a runner `::` lines are commands.)
  echo "error: the tag is not a release tag (v1.2.3 or v1.2.3-rc.1)" >&2
  exit 1
}
version=${tag#v}
$check_only && exit 0

# GitHub owner and repository names.
matches "$repo" '[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9._-]+' || {
  echo "error: the repository is not a GitHub owner/repo" >&2
  exit 1
}

VL_REPO=$repo VL_TAG=$tag VL_VERSION=$version
export VL_REPO VL_TAG VL_VERSION
for target in $targets; do
  file=$dir/vl-$target.tar.xz.sha256
  [ -f "$file" ] || { echo "error: $file is missing" >&2; exit 1; }
  sum=$(awk 'NR == 1 { print $1 }' "$file")
  case $sum in
    *[!0-9a-f]* | "") echo "error: $file does not hold a sha256" >&2; exit 1 ;;
  esac
  [ ${#sum} -eq 64 ] || { echo "error: $file does not hold a sha256" >&2; exit 1; }
  # Environment variable names cannot hold `-`.
  var=VL_SHA256_$(printf '%s' "$target" | tr '-' '_')
  export "$var=$sum"
done

# Replace each @NAME@ by its value, literally (index/substr, not gsub, whose
# replacement treats `&` and `\` specially).
out=$(VL_TARGETS=$targets awk '
  function replace(s, from, to,    i, r) {
    r = ""
    while ((i = index(s, from)) > 0) {
      r = r substr(s, 1, i - 1) to
      s = substr(s, i + length(from))
    }
    return r s
  }
  BEGIN {
    n = 0
    key[++n] = "@REPO@";    val[n] = ENVIRON["VL_REPO"]
    key[++n] = "@TAG@";     val[n] = ENVIRON["VL_TAG"]
    key[++n] = "@VERSION@"; val[n] = ENVIRON["VL_VERSION"]
    split(ENVIRON["VL_TARGETS"], t, " ")
    for (j in t) {
      v = "VL_SHA256_" t[j]
      gsub(/-/, "_", v)
      key[++n] = "@SHA256_" t[j] "@"; val[n] = ENVIRON[v]
    }
  }
  {
    line = $0
    for (j = 1; j <= n; j++) line = replace(line, key[j], val[j])
    print line
  }
' "$template")

if printf '%s\n' "$out" | grep -q '@[A-Za-z0-9_-]*@'; then
  echo "error: unfilled placeholders in the formula:" >&2
  printf '%s\n' "$out" | grep '@[A-Za-z0-9_-]*@' >&2
  exit 1
fi
printf '%s\n' "$out"
