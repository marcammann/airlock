# syntax=docker/dockerfile:1

ARG AIRLOCK_ARTIFACT_IMAGE=ghcr.io/marcammann/airlock:dev
ARG DAYTONA_PYTHON_IMAGE=mcr.microsoft.com/devcontainers/python:3.14

FROM ${AIRLOCK_ARTIFACT_IMAGE} AS airlock-artifact

FROM ${DAYTONA_PYTHON_IMAGE}

USER root

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  bind9-dnsutils \
  ca-certificates \
  curl \
  git \
  iputils-ping \
  netcat-openbsd \
  openssl \
  python3-pip \
  python3-venv \
  procps \
  ripgrep \
  sudo \
  && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --break-system-packages "litellm==1.83.7"

RUN set -eux; \
  if ! getent group airlock-writers >/dev/null; then \
  groupadd --system airlock-writers; \
  fi; \
  if ! getent group airlock >/dev/null; then \
  groupadd --system airlock; \
  fi; \
  if ! id -u airlock >/dev/null 2>&1; then \
  useradd --system --gid airlock --home-dir /var/lib/airlock --shell /usr/sbin/nologin airlock; \
  fi; \
  if ! id -u daytona >/dev/null 2>&1; then \
  useradd --create-home --shell /bin/bash daytona; \
  fi; \
  usermod -a -G airlock-writers daytona; \
  mkdir -p \
  /opt/airlock/bin \
  /opt/airlock/policies \
  /run/airlock/ca \
  /run/airlock/secrets \
  /run/daytona-secrets \
  /var/lib/airlock \
  /var/log/airlock \
  /workspace \
  /home/daytona; \
  chown -R airlock:airlock /run/airlock /var/lib/airlock; \
  chown -R airlock:airlock-writers /var/log/airlock; \
  chmod 2775 /var/log/airlock; \
  touch /var/log/airlock/proxy-worker.log; \
  chown airlock:airlock-writers /var/log/airlock/proxy-worker.log; \
  chmod 0664 /var/log/airlock/proxy-worker.log; \
  chown -R daytona:daytona /home/daytona /workspace; \
  chmod 0775 /workspace; \
  chown root:root /run/daytona-secrets; \
  chmod 0711 /run/daytona-secrets; \
  touch /run/daytona-secrets/secrets.env; \
  chown airlock:airlock-writers /run/daytona-secrets/secrets.env; \
  chmod 0620 /run/daytona-secrets/secrets.env; \
  chmod 0755 /run/airlock /run/airlock/ca; \
  chmod 0750 /run/airlock/secrets; \
  touch /home/daytona/.zshrc; \
  chown daytona:daytona /home/daytona/.zshrc

RUN set -eux; \
  printf '%s\n' \
  'daytona ALL=(airlock) NOPASSWD: /usr/local/bin/airlock-daytona-start-proxy' \
  >/etc/sudoers.d/airlock-daytona; \
  chmod 0440 /etc/sudoers.d/airlock-daytona; \
  visudo -cf /etc/sudoers.d/airlock-daytona

COPY --from=airlock-artifact /airlock-proxy-worker /opt/airlock/bin/airlock-proxy-worker
COPY policy/openai-api.yaml /opt/airlock/policies/openai-api.yaml
COPY start-proxy.sh /usr/local/bin/airlock-daytona-start-proxy

RUN chmod 0755 \
  /opt/airlock/bin/airlock-proxy-worker \
  /usr/local/bin/airlock-daytona-start-proxy

ENV AIRLOCK_POLICY_PATH=/opt/airlock/policies/openai-api.yaml
ENV AIRLOCK_PROXY_LISTEN=127.0.0.1:18080
ENV HTTP_PROXY=http://127.0.0.1:18080
ENV HTTPS_PROXY=http://127.0.0.1:18080
ENV http_proxy=http://127.0.0.1:18080
ENV https_proxy=http://127.0.0.1:18080
ENV NO_PROXY=localhost,127.0.0.1,::1
ENV no_proxy=localhost,127.0.0.1,::1
ENV AIRLOCK_CA_CERT=/run/airlock/ca/ca.crt
ENV SSL_CERT_FILE=/run/airlock/ca/ca.crt
ENV REQUESTS_CA_BUNDLE=/run/airlock/ca/ca.crt
ENV GIT_SSL_CAINFO=/run/airlock/ca/ca.crt
ENV NODE_EXTRA_CA_CERTS=/run/airlock/ca/ca.crt
ENV LITELLM_LOCAL_MODEL_COST_MAP=True

WORKDIR /workspace
USER daytona
ENTRYPOINT ["sleep", "infinity"]
