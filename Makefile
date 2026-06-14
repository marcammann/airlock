KIND_CLUSTER ?= airlock
KIND_CONFIG ?= deploy/kind/airlock.yaml
KUSTOMIZE_DIR ?= deploy/k8s
EXAMPLES_K8S_DIR ?= examples/k8s
SPIFFE_HELM_REPO ?= https://spiffe.github.io/helm-charts-hardened
SPIRE_VALUES ?= deploy/helm/spire/values.yaml
CONTROL_PLANE_IMAGE ?= airlock-control-plane:dev
PROXY_WORKER_IMAGE ?= airlock-proxy-worker:dev
WEB_UI_IMAGE ?= airlock-web-ui:dev

.PHONY: kind-up kind-down build-control-plane-image load-control-plane-image build-proxy-worker-image load-proxy-worker-image build-web-ui-image build-images load-images test-proxy-worker build-proxy-worker proxy-worker-local-smoke test-go-proxy-worker build-go-proxy-worker build-go-proxy-worker-image go-proxy-worker-local-smoke test-web-ui web-ui-dev install-spire install-vault install-airlock deploy-demo install-baseline demo-smoke local-control-plane-smoke spiffe-policy-smoke vault-jwt-setup k8s-egress-smoke injected-sidecar-smoke existing-envoy-smoke single-local-smoke security-smoke fail-closed-smoke fail-closed-k8s-smoke tls-termination-smoke envoy-sds-tls-smoke envoy-connect-sds-smoke github-connect-sds-smoke compose-git-demo compose-git-envoy-demo compose-git-no-control-plane-demo compose-git-clean compose-proxy-observability-up compose-proxy-observability-logs compose-proxy-observability-down compose-proxy-observability-clean opencode-headless-up opencode-headless-attach opencode-headless-logs opencode-headless-down opencode-headless-clean codex-app-server-up codex-app-server-connect codex-app-server-logs codex-app-server-down codex-app-server-clean test-e2e demo test

kind-up:
	kind create cluster --name $(KIND_CLUSTER) --config $(KIND_CONFIG)

kind-down:
	kind delete cluster --name $(KIND_CLUSTER)

build-control-plane-image:
	docker build -f control-plane/Dockerfile -t $(CONTROL_PLANE_IMAGE) .

load-control-plane-image:
	kind load docker-image $(CONTROL_PLANE_IMAGE) --name $(KIND_CLUSTER)

build-proxy-worker-image:
	docker build -f proxy-worker/Dockerfile -t $(PROXY_WORKER_IMAGE) .

build-web-ui-image:
	docker build -f web-ui/Dockerfile -t $(WEB_UI_IMAGE) web-ui

load-proxy-worker-image:
	kind load docker-image $(PROXY_WORKER_IMAGE) --name $(KIND_CLUSTER)

build-images: build-control-plane-image build-proxy-worker-image

load-images: load-control-plane-image load-proxy-worker-image

test-proxy-worker:
	cd proxy-worker && go test ./...

build-proxy-worker:
	mkdir -p dist
	cd proxy-worker && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../dist/airlock-proxy-worker ./cmd/airlock-proxy-worker

proxy-worker-local-smoke: build-proxy-worker
	./scripts/proxy-worker-local-smoke.sh

test-go-proxy-worker: test-proxy-worker

build-go-proxy-worker: build-proxy-worker

build-go-proxy-worker-image: build-proxy-worker-image

go-proxy-worker-local-smoke: proxy-worker-local-smoke

test-web-ui:
	cd web-ui && npm run lint && npm run build

web-ui-dev:
	cd web-ui && npm run dev -- --hostname 127.0.0.1 --port $${AIRLOCK_WEB_UI_PORT:-3000}

install-spire:
	helm repo add spiffe $(SPIFFE_HELM_REPO) --force-update
	helm repo update spiffe
	helm upgrade --install spire-crds spiffe/spire-crds --namespace spire-system
	helm upgrade --install spire spiffe/spire --namespace spire-system --values $(SPIRE_VALUES)
	kubectl rollout status statefulset/spire-server -n spire-system --timeout=180s
	kubectl rollout status daemonset/spire-agent -n spire-system --timeout=180s

install-vault:
	kubectl apply -f $(KUSTOMIZE_DIR)/namespaces.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/vault/vault-dev.yaml
	kubectl rollout status deployment/vault-dev -n vault --timeout=120s

install-airlock: build-control-plane-image load-control-plane-image
	kubectl apply -f $(KUSTOMIZE_DIR)/namespaces.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/crds/airlock.dev_secretproviderconfigs.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/crds/airlock.dev_airlockpolicies.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/crds/airlock.dev_airlockworkloads.yaml
	kubectl wait --for=condition=Established crd/secretproviderconfigs.airlock.dev --timeout=60s
	kubectl wait --for=condition=Established crd/airlockpolicies.airlock.dev --timeout=60s
	kubectl wait --for=condition=Established crd/airlockworkloads.airlock.dev --timeout=60s
	$(MAKE) install-spire
	kubectl apply -f $(KUSTOMIZE_DIR)/spire-system/airlock-spiffe-ids.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/airlock-system/control-plane-rbac.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/airlock-system/webhook-tls.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/airlock-system/control-plane-skeleton.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/airlock-system/injection-webhook.yaml
	kubectl rollout status deployment/airlock-control-plane -n airlock-system --timeout=120s

deploy-demo: build-proxy-worker-image load-proxy-worker-image install-vault
	kubectl apply -f $(KUSTOMIZE_DIR)/crds/airlock.dev_secretproviderconfigs.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/crds/airlock.dev_airlockpolicies.yaml
	kubectl apply -f $(KUSTOMIZE_DIR)/crds/airlock.dev_airlockworkloads.yaml
	kubectl wait --for=condition=Established crd/secretproviderconfigs.airlock.dev --timeout=60s
	kubectl wait --for=condition=Established crd/airlockpolicies.airlock.dev --timeout=60s
	kubectl wait --for=condition=Established crd/airlockworkloads.airlock.dev --timeout=60s
	kubectl apply -k $(EXAMPLES_K8S_DIR)/basic-egress
	kubectl rollout status deployment/airlock-proxy-worker -n demo --timeout=180s
	kubectl rollout status deployment/echo-upstream -n demo --timeout=120s
	kubectl rollout status deployment/code-agent -n demo --timeout=120s

install-baseline: install-airlock
	$(MAKE) deploy-demo

demo-smoke:
	./scripts/demo-smoke.sh

local-control-plane-smoke:
	./scripts/local-control-plane-smoke.sh

spiffe-policy-smoke:
	./scripts/spiffe-policy-smoke.sh

vault-jwt-setup:
	./scripts/vault-jwt-setup.sh

k8s-egress-smoke:
	./scripts/k8s-egress-smoke.sh

injected-sidecar-smoke:
	SMOKE_NAME=injected-sidecar WORKLOAD_DEPLOYMENT=code-agent-injected WORKLOAD_LABEL=app.kubernetes.io/name=code-agent-injected WORKLOAD_MANIFEST=$(EXAMPLES_K8S_DIR)/injected-sidecar/code-agent-injected.yaml ./scripts/k8s-egress-smoke.sh

existing-envoy-smoke:
	SMOKE_NAME=existing-envoy WORKLOAD_DEPLOYMENT=code-agent-existing-envoy WORKLOAD_LABEL=app.kubernetes.io/name=code-agent-existing-envoy WORKLOAD_MANIFEST=$(EXAMPLES_K8S_DIR)/existing-envoy/code-agent-existing-envoy.yaml ALLOW_SOURCE_ENVOY=true ./scripts/k8s-egress-smoke.sh

single-local-smoke:
	./scripts/single-local-smoke.sh

security-smoke:
	./scripts/security-smoke.sh

fail-closed-smoke:
	./scripts/fail-closed-smoke.sh

fail-closed-k8s-smoke:
	./scripts/fail-closed-k8s-smoke.sh

tls-termination-smoke:
	./scripts/tls-termination-smoke.sh

envoy-sds-tls-smoke:
	./scripts/envoy-sds-tls-smoke.sh

envoy-connect-sds-smoke:
	./scripts/envoy-connect-sds-smoke.sh

github-connect-sds-smoke:
	./scripts/github-connect-sds-smoke.sh

compose-git-demo:
	docker compose -f examples/compose/git/compose.yaml up --build --abort-on-container-exit --exit-code-from git-app

compose-git-envoy-demo:
	docker compose -f examples/compose/git/compose.envoy.yaml up --build --abort-on-container-exit --exit-code-from git-app

compose-git-no-control-plane-demo:
	docker compose -f examples/compose/git/compose.no-control-plane.yaml up --build --abort-on-container-exit --exit-code-from git-app

compose-git-clean:
	docker compose -f examples/compose/git/compose.yaml down -v
	docker compose -f examples/compose/git/compose.envoy.yaml down -v
	docker compose -f examples/compose/git/compose.no-control-plane.yaml down -v

compose-proxy-observability-up:
	docker compose -f examples/compose/proxy-observability/compose.yaml up -d --build

compose-proxy-observability-logs:
	docker compose -f examples/compose/proxy-observability/compose.yaml logs -f proxy-worker control-plane web-ui client

compose-proxy-observability-down:
	docker compose -f examples/compose/proxy-observability/compose.yaml down

compose-proxy-observability-clean:
	docker compose -f examples/compose/proxy-observability/compose.yaml down -v

opencode-headless-up:
	docker compose -f examples/compose/opencode-headless/compose.yaml up -d

opencode-headless-attach:
	opencode attach http://localhost:$${OPENCODE_PORT:-4096} --dir /workspace --username $${OPENCODE_SERVER_USERNAME:-opencode} --password $${OPENCODE_SERVER_PASSWORD:-opencode-local}

opencode-headless-logs:
	docker compose -f examples/compose/opencode-headless/compose.yaml logs -f opencode-server

opencode-headless-down:
	docker compose -f examples/compose/opencode-headless/compose.yaml down

opencode-headless-clean:
	docker compose -f examples/compose/opencode-headless/compose.yaml down -v

codex-app-server-up:
	docker compose -f examples/compose/codex-app-server/compose.yaml up -d --build

codex-app-server-connect:
	CODEX_REMOTE_AUTH_TOKEN=$$(cat examples/compose/codex-app-server/secrets/ws-token) codex --remote ws://127.0.0.1:$${CODEX_APP_SERVER_PORT:-4100} --remote-auth-token-env CODEX_REMOTE_AUTH_TOKEN

codex-app-server-logs:
	docker compose -f examples/compose/codex-app-server/compose.yaml logs -f codex-app-server

codex-app-server-down:
	docker compose -f examples/compose/codex-app-server/compose.yaml down

codex-app-server-clean:
	docker compose -f examples/compose/codex-app-server/compose.yaml down -v

test-e2e: demo-smoke vault-jwt-setup k8s-egress-smoke injected-sidecar-smoke existing-envoy-smoke security-smoke

demo: kind-up
	$(MAKE) install-baseline
	$(MAKE) test-e2e

test:
	cd control-plane && go test ./...
	cd proxy-worker && go test ./...
