MODULE  := github.com/vasyakrg/tgproxy-server
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.Date=$(DATE)

.DEFAULT_GOAL := help

.PHONY: help build generate test test-race lint vuln snapshot dev-certs run-server run-agent redis-up vendor-verify deploy

help: ## Список целей
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## Собрать bin/tgproxy
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tgproxy ./cmd/tgproxy

generate: ## templ generate
	go tool templ generate

test: ## go test ./...
	go test ./...

test-race: ## go test -race ./...
	go test -race ./...

lint: ## golangci-lint
	golangci-lint run

vuln: ## govulncheck
	go tool govulncheck ./...

snapshot: ## goreleaser snapshot
	goreleaser release --snapshot --clean

dev-certs: build ## Dev-сертификаты в dev/tls (идемпотентно)
	./bin/tgproxy pki dev-init --out dev/tls --agent local

run-server: build ## Запустить сервер с dev/server.yaml
	./bin/tgproxy server -c dev/server.yaml

run-agent: build ## Запустить агент с dev/agent.yaml
	./bin/tgproxy agent -c dev/agent.yaml

redis-up: ## Поднять dev-Redis (TLS)
	docker compose -f dev/docker-compose.yml up -d redis

vendor-verify: ## Проверить sha256 вендорных ассетов
	@cd web/static/vendor && \
	if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi

deploy: ## Деплой (M7)
	@echo "deploy: реализуется в M7" >&2; exit 1
