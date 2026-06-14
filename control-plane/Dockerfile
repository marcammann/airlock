# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25 AS build

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src/control-plane
COPY control-plane/go.mod control-plane/go.sum ./
RUN go mod download

COPY control-plane ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" go build -trimpath -ldflags="-s -w" -o /out/airlock-control-plane ./cmd/airlock-control-plane

FROM scratch
COPY --from=build /out/airlock-control-plane /airlock-control-plane
ENTRYPOINT ["/airlock-control-plane"]
