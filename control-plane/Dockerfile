FROM golang:1.25 AS build

WORKDIR /src/control-plane
COPY control-plane/go.mod control-plane/go.sum ./
RUN go mod download

COPY control-plane ./
RUN CGO_ENABLED=0 go build -o /out/airlock-control-plane ./cmd/airlock-control-plane

FROM scratch
COPY --from=build /out/airlock-control-plane /airlock-control-plane
ENTRYPOINT ["/airlock-control-plane"]
