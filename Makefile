BINARY   := pihole-mcp
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
IMAGE    ?= pihole-mcp:dev
# pinned tool versions (installed on demand with `go run`)
GOLANGCI ?= github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GOVULN   ?= golang.org/x/vuln/cmd/govulncheck@v1.1.4
DOCKER   ?= docker

.PHONY: licenses help build test cover fmt vet lint vuln check run-stdio run-http docker docker-multiarch docs check-docs inspector fixtures integration clean

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n",$$1,$$2}'

build: ## build ./bin/pihole-mcp
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/pihole-mcp

test: ## unit + in-memory MCP tests (never touches a real Pi-hole)
	go test -race -count=1 ./...

cover: ## tests with coverage report
	go test -race -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

fmt: ## gofmt everything
	gofmt -l -w .

vet:
	go vet ./...

lint: ## golangci-lint
	go run $(GOLANGCI) run ./...

vuln: ## govulncheck
	go run $(GOVULN) ./...

check: fmt vet test check-docs ## everything CI runs, except lint/vuln/docker

run-stdio: build ## run over stdio (needs PIHOLE_URL, PIHOLE_APP_PASSWORD)
	MCP_TRANSPORT=stdio ./bin/$(BINARY)

run-http: build ## run over HTTP on :8765 (needs PIHOLE_URL, PIHOLE_APP_PASSWORD, MCP_TOKEN)
	MCP_TRANSPORT=http ./bin/$(BINARY)

docker: ## build the image for this machine
	$(DOCKER) build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(IMAGE) .

docker-multiarch: ## build amd64+arm64+armv7 without pushing
	$(DOCKER) buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 --build-arg VERSION=$(VERSION) --output type=cacheonly .

docs: ## regenerate docs/tools.md from the registered tools
	go run ./cmd/pihole-mcp docs > docs/tools.md

check-docs: ## fail if docs/tools.md is stale
	@go run ./cmd/pihole-mcp docs | diff -u docs/tools.md - >/dev/null || (echo "docs/tools.md is stale: run 'make docs'" && exit 1)

inspector: build ## open the MCP Inspector against the stdio binary
	npx @modelcontextprotocol/inspector ./bin/$(BINARY)

fixtures: ## record SANITIZED fixtures from a live Pi-hole (read-only GETs) into testdata/recorded/
	./scripts/record-fixtures.sh

integration: ## read-only tests against a live Pi-hole (PIHOLE_URL, PIHOLE_APP_PASSWORD)
	go test -tags=integration -count=1 -run Integration -v ./internal/tools/

licenses: ## regenerate THIRD_PARTY_LICENSES.md from the linked modules
	python3 scripts/gen-third-party.py

clean:
	rm -rf bin dist coverage.out
