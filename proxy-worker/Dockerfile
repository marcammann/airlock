# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25 AS build

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src/proxy-worker
COPY proxy-worker/go.mod proxy-worker/go.sum ./
RUN go mod download
COPY proxy-worker ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" go build -trimpath -ldflags="-s -w" -o /out/airlock-proxy-worker ./cmd/airlock-proxy-worker

FROM scratch
COPY --from=build /out/airlock-proxy-worker /airlock-proxy-worker
ENTRYPOINT ["/airlock-proxy-worker"]
