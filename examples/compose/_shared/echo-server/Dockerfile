# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

WORKDIR /src
COPY examples/compose/_shared/echo-server/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/echo-server ./main.go

FROM scratch
COPY --from=build /out/echo-server /echo-server
ENTRYPOINT ["/echo-server"]
