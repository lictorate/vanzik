.PHONY: build build-mcp-gateway build-llm-proxy test test-all lint run clean docker docker-run release-artifacts require-api-key validate validate-examples bench dep-audit help

# Binary name
BINARY=vanzik
MCP_GATEWAY_BINARY=vanzik-mcp-gateway
LLM_PROXY_BINARY=vanzik-llm-proxy
VERSION=2.0.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)"

## build: Compile the binary
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/vanzik

## build-mcp-gateway: Compile the Vanzik MCP Gateway binary
build-mcp-gateway:
	go build $(LDFLAGS) -o $(MCP_GATEWAY_BINARY) ./cmd/vanzik-mcp-gateway

## build-llm-proxy: Compile the Vanzik LLM API Proxy binary
build-llm-proxy:
	go build $(LDFLAGS) -o $(LLM_PROXY_BINARY) ./cmd/vanzik-llm-proxy

## test: Run all tests with race detection
test:
	go test -v -race -coverprofile=coverage.out ./...

## test-all: Run every test suite (go, policy, python, ts) with summary
test-all:
	@./scripts/test-all.sh

## lint: Run linter
lint:
	golangci-lint run ./...

## run: Build and start with default policy + dashboard
run: build
	./$(BINARY) server --policy configs/default.yaml --dashboard --watch

## validate: Validate the starter policy and every example policy
validate: build
	@for f in configs/default.yaml configs/examples/*.yaml; do \
		echo "Validating $$f..."; \
		./$(BINARY) validate --strict --policy $$f || exit 1; \
	done
	@echo "All policies valid."

## ----- Validation -----

## validate-examples: Validate configs/default.yaml and every YAML in configs/examples/
validate-examples: build
	@set -e; \
	for f in configs/default.yaml configs/examples/*.yaml; do \
		echo "Validating $$f"; \
		./$(BINARY) validate --strict --policy $$f; \
	done
	@echo "All example policies valid."

## docker: Build Docker image
docker:
	docker build --build-arg COMMIT=$(COMMIT) -t $(BINARY):$(VERSION) -t $(BINARY):latest .

## docker-run: Run in Docker (needs VANZIK_API_KEY in the environment)
docker-run: require-api-key docker
	docker run -d -p 8080:8080 --name vanzik \
		-e VANZIK_API_KEY \
		-v vanzik-audit:/var/lib/vanzik \
		$(BINARY):latest

## release-artifacts: Build the release archives for every platform into dist/ (what the release workflow uploads)
release-artifacts:
	./scripts/build-release.sh --version $(VERSION) --commit $(COMMIT) --out dist

# Without an API key the server binds 127.0.0.1 inside the container, so
# the published port is unreachable. Fail before building the image.
require-api-key:
	@test -n "$$VANZIK_API_KEY" || { echo "VANZIK_API_KEY is not set. Without it the server binds the container's own loopback and -p 8080:8080 is unreachable. Example: export VANZIK_API_KEY=\"\$$(openssl rand -hex 32)\"" >&2; exit 1; }

## clean: Remove build artifacts
clean:
	rm -f $(BINARY) $(MCP_GATEWAY_BINARY) $(LLM_PROXY_BINARY) coverage.out
	rm -rf dist/

## install-python-sdk: Install the Python SDK in development mode
install-python-sdk:
	cd plugins/python && pip install -e ".[all]"

## install-ts-sdk: Build the TypeScript SDK
install-ts-sdk:
	cd plugins/typescript && npm install && npm run build

## ----- Dependency audit -----

## dep-audit: Audit every dependency (Go/Python/TS) for known vulns + perf regressions
dep-audit:
	@echo "Dependency safety gate (security + performance)..."
	@go test -run '^TestDependencyAudit_Gate$$' -count=1 ./pkg/depaudit
	@echo "Dependency audit report (current vs latest)..."
	@DEPAUDIT_ONLINE=1 go test -run '^TestDependencyAudit_Report$$' -count=1 -v ./pkg/depaudit

## ----- Benchmarks -----

## bench: Run all Go benchmarks (no race; allocations reported)
bench:
	go test -bench=. -benchmem -run=^$$ ./...

## help: Show this help
help:
	@echo "Vanzik — The firewall for AI agents\n"
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
