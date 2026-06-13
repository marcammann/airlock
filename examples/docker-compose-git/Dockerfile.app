FROM golang:1.25 AS proxy-worker-build

WORKDIR /src/proxy-worker
COPY proxy-worker/go.mod proxy-worker/go.sum ./
RUN go mod download
COPY proxy-worker ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/airlock-proxy-worker ./cmd/airlock-proxy-worker

FROM alpine:3.20

RUN apk add --no-cache \
    ca-certificates \
    git \
    openssl \
    su-exec

RUN addgroup -S airlock \
    && adduser -S -G airlock -h /var/lib/airlock -s /sbin/nologin airlock \
    && addgroup -S appuser \
    && adduser -S -G appuser -h /home/appuser appuser \
    && mkdir -p /run/airlock/ca /run/airlock/secrets /var/lib/airlock /work \
    && chown -R airlock:airlock /run/airlock /var/lib/airlock \
    && chown -R appuser:appuser /home/appuser /work \
    && chmod 0755 /run/airlock/ca \
    && chmod 0700 /run/airlock/secrets

COPY --from=proxy-worker-build /out/airlock-proxy-worker /usr/local/bin/airlock-proxy-worker
COPY examples/docker-compose-git/entrypoint.sh /usr/local/bin/airlock-compose-git-entrypoint

RUN chmod 0755 /usr/local/bin/airlock-compose-git-entrypoint /usr/local/bin/airlock-proxy-worker

ENTRYPOINT ["/usr/local/bin/airlock-compose-git-entrypoint"]
