# syntax=docker/dockerfile:1

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
