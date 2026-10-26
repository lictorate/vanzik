# Build stage
# Must stay >= the `go` directive in go.mod (go1.26.10), the minimum toolchain,
# which carries the stdlib fixes govulncheck gates on — see that file for the
# advisory list. A builder older than that minimum still works (Go downloads the
# required toolchain) but silently adds a download to every image build, so keep
# these two in step.
#
# Both base images are pinned by their multi-arch index digest (the tag is kept
# for readability); Dependabot's docker ecosystem keeps the digests current.
#
# The builder runs on the build host's own platform and cross-compiles for the
# target (TARGETOS/TARGETARCH, set by BuildKit for each `--platform`). Every
# dependency is pure Go, so CGO stays off and a multi-arch image needs no CPU
# emulation. A plain `docker build` targets the host.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
# COMMIT feeds `vanzik version` and the CLI update check (`make docker`
# passes the git short hash). Left at "dev", the binary falls back to Go build
# info, as a plain `go build` does.
ARG COMMIT=dev
ARG TARGETOS=linux
ARG TARGETARCH
# All three binaries go into the image so the MCP gateway and LLM proxy can run
# from it too (`--entrypoint vanzik-llm-proxy`); the default entrypoint
# stays the enforcement server.
RUN for b in vanzik vanzik-mcp-gateway vanzik-llm-proxy; do \
        CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
            go build -trimpath -ldflags="-s -w -X main.commit=${COMMIT}" -o /out/$b ./cmd/$b || exit 1; \
    done

# Runtime stage
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f

RUN apk --no-cache add ca-certificates \
    && addgroup -S vanzik \
    && adduser -S -G vanzik -u 10001 vanzik \
    && mkdir -p /var/lib/vanzik \
    && chown -R vanzik:vanzik /var/lib/vanzik

COPY --from=builder /out/ /usr/local/bin/
COPY configs/default.yaml /etc/vanzik/default.yaml

# Tells the CLI's update notice that this copy updates by pulling a new image,
# not by re-running the one-line installer.
ENV VANZIK_DISTRIBUTION=container

# Run as non-root. /var/lib/vanzik is the default writable location for
# the audit log; mount a volume here in production so the log survives
# container restarts.
USER vanzik:vanzik
WORKDIR /var/lib/vanzik

# GOMEMLIMIT is deliberately NOT hardcoded: the right value is the container's
# memory limit, which is only known at run time. Without it the Go runtime is
# unaware of the cgroup ceiling and can be OOM-killed under GC pressure rather
# than collecting harder. Set it to ~90% of the container limit, e.g.
#   docker run -m 512m -e GOMEMLIMIT=460MiB ...
# or in Kubernetes via a resourceFieldRef on limits.memory.

EXPOSE 8080

# Liveness for orchestrators. /health is unauthenticated by design and the
# server binds 127.0.0.1 unless --api-key is set, so the probe runs from inside
# the container against loopback. NOTE: this reports "process is serving", not
# "state hydration succeeded" — a boot where hydration failed still answers
# 200. Use it for restarts, not as an enforcement-readiness signal.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["vanzik"]
CMD ["server", "--policy", "/etc/vanzik/default.yaml", "--dashboard", "--audit-log", "/var/lib/vanzik/audit.jsonl"]
