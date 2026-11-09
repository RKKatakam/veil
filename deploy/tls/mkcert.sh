#!/usr/bin/env bash
# Make a private certificate authority and one server certificate for the
# names and addresses given, for a Veil deployment (docs/DEPLOY.md). The
# server's built-in self-signed certificate names only localhost and
# 127.0.0.1; anything reached by another name needs a certificate like this
# one, which clients pin with `vl login --ca ca.pem` (veil-bench: `--ca`).
#
#   deploy/tls/mkcert.sh OUT_DIR NAME_OR_IP...
#
# Writes OUT_DIR/ca.pem, server.pem and server-key.pem. The server key is
# world-readable (0644), and OUT_DIR traversable (0755), so that the
# server, running as uid 10001 inside its container, can read the
# bind-mounted key; the CA's key (ca-key.pem) stays 0600. Keep OUT_DIR out
# of version control (.gitignore covers deploy/compose/.tls and deploy/do/state).
set -euo pipefail
OUT=${1:?output directory}; shift
[ $# -gt 0 ] || { echo "mkcert: give at least one name or IP" >&2; exit 2; }
umask 077
mkdir -p "$OUT"; chmod 755 "$OUT"
san=""
for n in "$@"; do
    if [[ "$n" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$n" == *:* ]]; then san+="IP:$n,"; else san+="DNS:$n,"; fi
done
san=${san%,}
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$OUT/ca-key.pem" -out "$OUT/ca.pem" \
    -subj "/CN=Veil test CA" -days 30 -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$OUT/server-key.pem" -out "$OUT/server.csr" \
    -subj "/CN=$1" >/dev/null 2>&1
cat > "$OUT/server.ext" <<EXT
subjectAltName=$san
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca-key.pem" -CAcreateserial \
    -out "$OUT/server.pem" -days 30 -extfile "$OUT/server.ext" >/dev/null 2>&1
rm -f "$OUT/server.csr" "$OUT/server.ext" "$OUT/ca.srl"
chmod 644 "$OUT/ca.pem" "$OUT/server.pem" "$OUT/server-key.pem"
chmod 600 "$OUT/ca-key.pem"
echo "mkcert: $OUT/server.pem for $san (CA: $OUT/ca.pem, valid 30 days)"
