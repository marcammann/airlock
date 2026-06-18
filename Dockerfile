# syntax=docker/dockerfile:1

# ---------- external spire images ----------
FROM ghcr.io/spiffe/spire-server:1.12.4 AS spire-server
FROM ghcr.io/spiffe/spire-agent:1.12.4 AS spire-agent

# ---------- build stage ----------
FROM --platform=$BUILDPLATFORM golang:1.26 AS build

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY api ./api
COPY cmd ./cmd
COPY internal ./internal

RUN mkdir -p /out \
  && CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

# ---------- control-plane ----------
FROM scratch AS control-plane
COPY --from=build /out/airlock-control-plane /airlock-control-plane
ENTRYPOINT ["/airlock-control-plane"]

# ---------- proxy-worker ----------
FROM scratch AS proxy-worker
COPY --from=build /out/airlock-proxy-worker /airlock-proxy-worker
ENTRYPOINT ["/airlock-proxy-worker"]

# ---------- spire (server + agent binaries) ----------
FROM alpine:3.22 AS spire
RUN apk add --no-cache ca-certificates
COPY --from=spire-server /opt/spire/bin/spire-server /usr/local/bin/spire-server
COPY --from=spire-agent /opt/spire/bin/spire-agent /usr/local/bin/spire-agent

# ---------- control-plane-spiffe (control-plane + spire-agent) ----------
FROM alpine:3.22 AS control-plane-spiffe
RUN apk add --no-cache ca-certificates su-exec \
    && adduser -D -u 1001 airlock-control
COPY --from=spire-agent /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
COPY --from=build /out/airlock-control-plane /airlock-control-plane
COPY examples/compose/spiffe-envoy/airlock-spire-entrypoint.sh /usr/local/bin/airlock-spire-entrypoint
RUN chmod 0755 /usr/local/bin/airlock-spire-entrypoint
ENTRYPOINT ["/usr/local/bin/airlock-spire-entrypoint"]

# ---------- proxy-worker-spiffe (proxy-worker + spire-agent) ----------
FROM alpine:3.22 AS proxy-worker-spiffe
RUN apk add --no-cache ca-certificates su-exec \
    && adduser -D -u 1002 airlock-proxy
COPY --from=spire-agent /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
COPY --from=build /out/airlock-proxy-worker /airlock-proxy-worker
COPY examples/compose/spiffe-envoy/airlock-spire-entrypoint.sh /usr/local/bin/airlock-spire-entrypoint
RUN chmod 0755 /usr/local/bin/airlock-spire-entrypoint
ENTRYPOINT ["/usr/local/bin/airlock-spire-entrypoint"]
