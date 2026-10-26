MODULE  := github.com/vasyakrg/tgproxy-server
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.Date=$(DATE)

.DEFAULT_GOAL := help

.PHONY: help build generate test test-race lint vuln snapshot deb dev-certs dev-setup run-server run-agent run-agent2 redis-up dev-target-up dev-target-down dev-packages vendor-verify deploy

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

snapshot: ## goreleaser snapshot (архивы + deb в dist/, без подписи)
	goreleaser release --snapshot --clean --skip=sign

deb: ## Только deb (linux/amd64) в dist/, без архивов и подписи
	goreleaser release --snapshot --clean --skip=sign,archive

dev-certs: build ## CA в dev/data/tgproxy.db (KEK + `pki init`) и сертификаты dev-агентов local, local2 в dev/tls (идемпотентно)
	@mkdir -p dev/data dev/tls
	@rm -f dev/tls/ca.key dev/tls/server-client.crt dev/tls/server-client.key
	./bin/tgproxy pki kek-init --out dev/data/kek
	./bin/tgproxy pki init -c dev/server.yaml
	./bin/tgproxy pki dev-agents -c dev/server.yaml --out dev/tls --agent local --agent local2

dev-setup: dev-certs ## dev-certs + права dev/users.yml (после этого `make run-server` без ручных шагов)
	chmod 0640 dev/users.yml

run-server: build ## Запустить сервер с dev/server.yaml
	./bin/tgproxy server -c dev/server.yaml

run-agent: build ## Запустить агент с dev/agent.yaml
	./bin/tgproxy agent -c dev/agent.yaml

run-agent2: build ## Запустить второй агент с dev/agent2.yaml (:8445)
	./bin/tgproxy agent -c dev/agent2.yaml

redis-up: ## Поднять dev-Redis (TLS)
	docker compose -f dev/docker-compose.yml up -d redis

bin/tgproxy-linux: $(shell find cmd internal -name '*.go' -not -name '*_test.go')
	CGO_ENABLED=0 GOOS=linux GOARCH=$(shell go env GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tgproxy-linux ./cmd/tgproxy

dev-target-up: bin/tgproxy-linux ## Поднять sshd-debian (debian:12+systemd, :2222) и nat-agent (reverse, без портов)
	cp bin/tgproxy-linux dev/nat-agent/tgproxy
	docker compose -f dev/docker-compose.yml up -d --build sshd-debian nat-agent

dev-target-down: ## Остановить sshd-debian и nat-agent
	docker compose -f dev/docker-compose.yml rm -sf sshd-debian nat-agent

dev-packages: ## Собрать deb под архитектуру docker и положить в dev/data/packages (кэш установщика)
	@mkdir -p dev/data/packages
	cp "$$(packaging/ci/native-deb.sh)" dev/data/packages/

vendor-verify: ## Проверить sha256 вендорных ассетов
	@cd web/static/vendor && \
	if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi

deploy: ## Деплой (M7)
	@echo "deploy: реализуется в M7" >&2; exit 1
