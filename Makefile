MODULE  := github.com/vasyakrg/tgproxy-server
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.Date=$(DATE)

.DEFAULT_GOAL := help

.PHONY: help build generate test test-race lint vuln snapshot deb dev-certs dev-setup run-server run-agent run-agent2 redis-up dev-target-up dev-target-down dev-keys build-dev dev-packages vendor-verify deploy release-dry fuzz gosec bench geoip

help: ## Список целей
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## Собрать bin/tgproxy
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tgproxy ./cmd/tgproxy

generate: ## templ generate
	go tool templ generate

test: ## go test ./...
	go test ./...

bench: ## Нагрузочный smoke (500 rps getMe, vegeta; пороги из M7-T2)
	go run ./scripts/bench

test-race: ## go test -race ./...
	go test -race ./...

lint: ## golangci-lint
	golangci-lint run

FUZZTIME ?= 60s
FUZZ_TARGETS := ./internal/tgapi:FuzzParsePath ./internal/tgapi:FuzzParseEnvelope \
	./internal/redact:FuzzString ./internal/redact:FuzzKeys \
	./internal/server/web/auth:FuzzParsePHC ./internal/server/router:FuzzExtractChatID \
	./internal/selfupdate:FuzzParseRequest ./internal/deployhelper:FuzzArgs

fuzz: ## фаззеры (FUZZTIME=60s на каждый)
	@set -e; for t in $(FUZZ_TARGETS); do \
		echo "== fuzz $${t#*:} ($(FUZZTIME))"; \
		go test "$${t%%:*}" -run='^$$' -fuzz="^$${t#*:}$$" -fuzztime=$(FUZZTIME); \
	done

gosec: ## gosec (исключения только #nosec Gxxx -- причина)
	go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 -quiet -exclude-generated ./...

vuln: ## govulncheck
	go tool govulncheck ./...

geoip: ## Скачать базу стран DB-IP Lite в build/geoip (для deb; в git не коммитится)
	scripts/geoip/fetch.sh build/geoip/dbip-country-lite.mmdb

snapshot: ## goreleaser snapshot (архивы + deb в dist/, без подписи)
	goreleaser release --snapshot --clean --skip=sign

deb: ## Только deb (linux/amd64) в dist/, без архивов и подписи
	goreleaser release --snapshot --clean --skip=sign,archive

release-dry: ## Полный dry-run релиза без подписи/публикации + smoke deb (нужен docker)
	goreleaser release --snapshot --clean --skip=publish,sign
	@if [ "$$(docker info --format '{{.Architecture}}')" = x86_64 ]; then packaging/ci/smoke.sh dist/tgproxy_*_amd64.deb; else echo "arm64-хост: smoke на нативно собранном deb (amd64-deb из dist не установить)"; packaging/ci/smoke.sh; fi

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

dev-keys: ## Dev-ключ minisign в dev/data/minisign.{key,pub} (gitignored, идемпотентно); НЕ для релиза
	@go run ./scripts/devsign keygen --dir dev/data

build-dev: dev-keys ## Как build, но с вшитым dev-pubkey (release.pubKeysCSV) — только для локального стенда
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS) -X $(MODULE)/internal/release.pubKeysCSV=$$(go run ./scripts/devsign pubkey --dir dev/data)" -o bin/tgproxy ./cmd/tgproxy

dev-packages: dev-keys ## Собрать deb (с dev-pubkey) под архитектуру docker, подписать dev-ключом → dev/data/packages/<v>/ (кэш установщика)
	@rm -rf dev/data/packages && mkdir -p dev/data/packages
	@deb="$$(TGPROXY_PUBKEYS="$$(go run ./scripts/devsign pubkey --dir dev/data)" packaging/ci/native-deb.sh)" && \
		go run ./scripts/devsign sign --key dev/data/minisign.key --out dev/data/packages "$$deb"

vendor-verify: ## Проверить sha256 вендорных ассетов
	@cd web/static/vendor && \
	if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi

deploy: ## Деплой сервера на прод (deploy/.env; DEPLOY_DRY_RUN=1 — только план; DEPLOY_MODE=release DEPLOY_TAG=vX.Y.Z)
	@scripts/deploy.sh
