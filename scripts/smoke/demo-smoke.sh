#!/usr/bin/env sh
set -eu

kubectl rollout status statefulset/spire-server -n spire-system --timeout=180s
kubectl rollout status daemonset/spire-agent -n spire-system --timeout=180s
kubectl exec -n demo deploy/code-agent -- \
  curl -fsS \
  'http://vault.vault.svc.cluster.local:8200/v1/sys/health?standbyok=true&sealedcode=204&uninitcode=204'
kubectl exec -n demo deploy/code-agent -- \
  curl -fsS http://echo-upstream.demo.svc.cluster.local:8080/hostname
