# syntax=docker/dockerfile:1.7
# Veil's container images (docs/DEPLOY.md). One build stage compiles the
# release binaries once; two runtime targets take what they need:
#
#   docker build -f deploy/docker/Dockerfile --target server -t veil-server:TAG .
#   docker build -f deploy/docker/Dockerfile --target bench  -t veil-bench:TAG .
#
# (`deploy/docker/build.sh` runs both.) Base images are pinned to exact
# versions; nothing secret is baked in: credentials come from the
# environment at run time (VEIL_S3_ACCESS_KEY, VEIL_S3_SECRET_KEY,
# VEIL_DATABASE_URL) and the TLS key from a mounted file.

# ---- build: the same toolchain as the repository (rust-toolchain: 1.99.1) ----
FROM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
# jemalloc (the server's allocator) is built from source: make and a C
# compiler, both in this image. `--locked` keeps the build at Cargo.lock.
WORKDIR /src
COPY . .
ENV CARGO_INCREMENTAL=0 CARGO_NET_RETRY=10
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release -p vl -p veil-server -p veil-bench \
    && mkdir -p /out && cp target/release/vl target/release/veil-server target/release/veil-bench /out/ \
    && strip /out/vl /out/veil-server /out/veil-bench

# ---- server: veil-server (the Hub), also `veil-server cache` and `migrate` ----
FROM debian:12.12-slim@sha256:d5d3f9c23164ea16f31852f95bd5959aad1c5e854332fe00f7b3a20fcc9f635c AS server
ARG VEIL_COMMIT=unknown
LABEL org.opencontainers.image.title="veil-server" \
      org.opencontainers.image.revision="$VEIL_COMMIT" \
      org.opencontainers.image.source="https://github.com/veil-vcs/veil"
# ca-certificates: S3 over HTTPS (Spaces). curl: the health check only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 veil \
    && useradd -u 10001 -g veil -d /var/lib/veil -m -s /usr/sbin/nologin veil \
    && mkdir -p /var/lib/veil-cache && chown veil:veil /var/lib/veil-cache
COPY --from=build /out/veil-server /usr/local/bin/veil-server
USER veil:veil
WORKDIR /var/lib/veil
VOLUME ["/var/lib/veil"]
EXPOSE 8443
# Healthy when the server answers HTTPS on its port with 2xx or 4xx (the
# route needs a grant, so an unauthenticated 401 means "up", while 000 or
# 5xx fails). A cache sets VEIL_HEALTH_URL to its own port. HTTP/1.1: a
# cache from before BUG-1592's fix advertises h2 but serves HTTP/1 only,
# which breaks an HTTP/2 client's stream.
ENV VEIL_HEALTH_URL=https://127.0.0.1:8443/v1/epochs
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD case "$(curl -ksS --http1.1 -o /dev/null -w '%{http_code}' --max-time 2 "$VEIL_HEALTH_URL")" in 2*|4*) exit 0;; *) exit 1;; esac
ENTRYPOINT ["/usr/local/bin/veil-server"]

# ---- bench: the load driver (veil-bench, vl, veil-server, git) ----
# veil-bench's openscion, run and `--via cache` cases start a server of
# their own (and Git is the OpenScion reference), so the driver carries all
# three binaries.
FROM debian:12.12-slim@sha256:d5d3f9c23164ea16f31852f95bd5959aad1c5e854332fe00f7b3a20fcc9f635c AS bench
ARG VEIL_COMMIT=unknown
LABEL org.opencontainers.image.title="veil-bench" \
      org.opencontainers.image.revision="$VEIL_COMMIT" \
      org.opencontainers.image.source="https://github.com/veil-vcs/veil"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10002 bench \
    && useradd -u 10002 -g bench -d /work -m -s /usr/sbin/nologin bench \
    && mkdir -p /work/tmp /work/results && chown -R bench:bench /work
COPY --from=build /out/vl /out/veil-server /out/veil-bench /usr/local/bin/
# Git commits in the OpenScion reference need an author.
ENV GIT_AUTHOR_NAME=veil-bench GIT_AUTHOR_EMAIL=bench@veil.invalid \
    GIT_COMMITTER_NAME=veil-bench GIT_COMMITTER_EMAIL=bench@veil.invalid \
    HOME=/work TMPDIR=/work/tmp
USER bench:bench
WORKDIR /work
VOLUME ["/work"]
ENTRYPOINT ["/usr/local/bin/veil-bench"]
CMD ["--help"]
