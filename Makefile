KIND_CLUSTER ?= airlock
KIND_CONFIG ?= deploy/kind/airlock.yaml
KUSTOMIZE_DIR ?= deploy/k8s
EXAMPLES_K8S_DIR ?= examples/k8s
SPIFFE_HELM_REPO ?= https://spiffe.github.io/helm-charts-hardened
SPIRE_VALUES ?= deploy/helm/spire/values.yaml
CONTROL_PLANE_IMAGE ?= airlock-control-plane:dev
PROXY_WORKER_IMAGE ?= airlock-proxy-worker:dev
WEB_UI_IMAGE ?= airlock-web-ui:dev
AIRLOCK_ARTIFACT_IMAGE ?= ghcr.io/marcammann/airlock:dev
AIRLOCK_ARTIFACT_REMOTE_IMAGE ?= ghcr.io/marcammann/airlock:dev
AIRLOCK_IMAGE_PLATFORMS ?= linux/amd64,linux/arm64
GO_TEST_PACKAGES ?= ./... ./examples/compose/_shared/echo-server
SMOKE_SCRIPTS_DIR ?= scripts/smoke
AIRLOCK_ARTIFACT_DOCKERFILE ?= build/package/Dockerfile.artifacts

.PHONY: kind-up kind-down build-control-plane-image load-control-plane-image build-proxy-worker-image load-proxy-worker-image build-airlock-artifact-image push-airlock-artifact-image build-web-ui-image build-images load-images test-proxy-worker build-proxy-worker proxy-worker-local-smoke test-go-proxy-worker build-go-proxy-worker build-go-proxy-worker-image go-proxy-worker-local-smoke test-web-ui web-ui-dev install-spire install-vault install-airlock deploy-demo install-baseline demo-smoke local-control-plane-smoke spiffe-policy-smoke vault-jwt-setup k8s-egress-smoke injected-sidecar-smoke existing-envoy-smoke single-local-smoke security-smoke fail-closed-smoke fail-closed-k8s-smoke tls-termination-smoke envoy-sds-tls-smoke envoy-connect-sds-smoke github-connect-sds-smoke test-e2e demo build-go test-go test-race lint check test

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

build-airlock-artifact-image:
	docker buildx build --load -f $(AIRLOCK_ARTIFACT_DOCKERFILE) -t $(AIRLOCK_ARTIFACT_IMAGE) .

push-airlock-artifact-image:
	docker buildx build --platform $(AIRLOCK_IMAGE_PLATFORMS) -f $(AIRLOCK_ARTIFACT_DOCKERFILE) -t $(AIRLOCK_ARTIFACT_REMOTE_IMAGE) --push .

build-web-ui-image:
	docker build -f web-ui/Dockerfile -t $(WEB_UI_IMAGE) web-ui

load-proxy-worker-image:
	kind load docker-image $(PROXY_WORKER_IMAGE) --name $(KIND_CLUSTER)

build-images: build-control-plane-image build-proxy-worker-image

load-images: load-control-plane-image load-proxy-worker-image

test-proxy-worker:
	go test ./cmd/airlock-proxy-worker ./internal/proxyworker

build-proxy-worker:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/airlock-proxy-worker ./cmd/airlock-proxy-worker

proxy-worker-local-smoke: build-proxy-worker
	./$(SMOKE_SCRIPTS_DIR)/proxy-worker-local-smoke.sh

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
	./$(SMOKE_SCRIPTS_DIR)/demo-smoke.sh

local-control-plane-smoke:
	./$(SMOKE_SCRIPTS_DIR)/local-control-plane-smoke.sh

spiffe-policy-smoke:
	./$(SMOKE_SCRIPTS_DIR)/spiffe-policy-smoke.sh

vault-jwt-setup:
	./$(EXAMPLES_K8S_DIR)/vault-jwt-setup.sh

k8s-egress-smoke:
	./$(SMOKE_SCRIPTS_DIR)/k8s-egress-smoke.sh

injected-sidecar-smoke:
	SMOKE_NAME=injected-sidecar WORKLOAD_DEPLOYMENT=code-agent-injected WORKLOAD_LABEL=app.kubernetes.io/name=code-agent-injected WORKLOAD_MANIFEST=$(EXAMPLES_K8S_DIR)/injected-sidecar/code-agent-injected.yaml ./$(SMOKE_SCRIPTS_DIR)/k8s-egress-smoke.sh

existing-envoy-smoke:
	SMOKE_NAME=existing-envoy WORKLOAD_DEPLOYMENT=code-agent-existing-envoy WORKLOAD_LABEL=app.kubernetes.io/name=code-agent-existing-envoy WORKLOAD_MANIFEST=$(EXAMPLES_K8S_DIR)/existing-envoy/code-agent-existing-envoy.yaml ALLOW_SOURCE_ENVOY=true ./$(SMOKE_SCRIPTS_DIR)/k8s-egress-smoke.sh

single-local-smoke:
	./$(SMOKE_SCRIPTS_DIR)/single-local-smoke.sh

security-smoke:
	./$(SMOKE_SCRIPTS_DIR)/security-smoke.sh

fail-closed-smoke:
	./$(SMOKE_SCRIPTS_DIR)/fail-closed-smoke.sh

fail-closed-k8s-smoke:
	./$(SMOKE_SCRIPTS_DIR)/fail-closed-k8s-smoke.sh

tls-termination-smoke:
	./$(SMOKE_SCRIPTS_DIR)/tls-termination-smoke.sh

envoy-sds-tls-smoke:
	./$(SMOKE_SCRIPTS_DIR)/envoy-sds-tls-smoke.sh

envoy-connect-sds-smoke:
	./$(SMOKE_SCRIPTS_DIR)/envoy-connect-sds-smoke.sh

github-connect-sds-smoke:
	./$(SMOKE_SCRIPTS_DIR)/github-connect-sds-smoke.sh

test-e2e: demo-smoke vault-jwt-setup k8s-egress-smoke injected-sidecar-smoke existing-envoy-smoke security-smoke

demo: kind-up
	$(MAKE) install-baseline
	$(MAKE) test-e2e

build-go:
	go build $(GO_TEST_PACKAGES)

test-go:
	go test $(GO_TEST_PACKAGES)

test-race:
	go test -race $(GO_TEST_PACKAGES)

lint:
	golangci-lint run

check: build-go test-race lint

test: test-go
