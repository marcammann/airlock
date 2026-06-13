FROM golang:1.25 AS build

WORKDIR /src/proxy-worker
COPY proxy-worker/go.mod proxy-worker/go.sum ./
RUN go mod download
COPY proxy-worker ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/airlock-proxy-worker ./cmd/airlock-proxy-worker

FROM scratch
COPY --from=build /out/airlock-proxy-worker /airlock-proxy-worker
ENTRYPOINT ["/airlock-proxy-worker"]
