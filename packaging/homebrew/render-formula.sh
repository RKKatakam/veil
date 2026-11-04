#!/bin/sh
# Render packaging/homebrew/vl.rb.in into a Homebrew formula on stdout.
#
#   render-formula.sh <tag> <artifacts-dir> [<owner/repo>]
#
# <tag> is the release tag (`v1.0.0`); <artifacts-dir> holds the
# `vl-<target>.tar.xz.sha256` files of that release (dist writes them next
# to the archives; `gh release download <tag> -p '*.sha256'` fetches them).
# <owner/repo> defaults to $GITHUB_REPOSITORY, then veil-vcs/veil.
set -eu

[ $# -ge 2 ] || { echo "usage: $0 <tag> <artifacts-dir> [<owner/repo>]" >&2; exit 2; }
tag=$1
dir=$2
repo=${3:-${GITHUB_REPOSITORY:-veil-vcs/veil}}
version=${tag#v}
template=$(dirname "$0")/vl.rb.in

case $version in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "error: $tag does not look like a release tag (v1.2.3)" >&2; exit 1 ;;
esac

script="s|@REPO@|$repo|g; s|@TAG@|$tag|g; s|@VERSION@|$version|g"
for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
  file=$dir/vl-$target.tar.xz.sha256
  [ -f "$file" ] || { echo "error: $file is missing" >&2; exit 1; }
  sum=$(awk 'NR == 1 { print $1 }' "$file")
  case $sum in
    *[!0-9a-f]* | "") echo "error: $file does not hold a sha256" >&2; exit 1 ;;
  esac
  [ ${#sum} -eq 64 ] || { echo "error: $file does not hold a sha256" >&2; exit 1; }
  script="$script; s|@SHA256_$target@|$sum|g"
done

out=$(sed "$script" "$template")
if printf '%s\n' "$out" | grep -q '@[A-Za-z0-9_-]*@'; then
  echo "error: unfilled placeholders in the formula:" >&2
  printf '%s\n' "$out" | grep '@[A-Za-z0-9_-]*@' >&2
  exit 1
fi
printf '%s\n' "$out"
