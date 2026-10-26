# tgproxy-server

Прокси для Telegram Bot API: `server` принимает запросы ботов, `agent` (в другом сегменте сети/за NAT) ходит в `api.telegram.org`. Один бинарь `tgproxy`, связь server ↔ agent по mTLS.

![tgproxy server + agent](docs/tgproxy-server-agent.svg)

## Документация

- [docs/architecture.md](docs/architecture.md) — архитектура (источник правды)
- [docs/plan.md](docs/plan.md) — план реализации по вехам

## Make-цели

`make help` — полный список. Основные: `build`, `generate`, `test`, `test-race`, `lint`, `vuln`, `snapshot`, `dev-certs`, `dev-setup`, `run-server`, `run-agent`, `redis-up`, `vendor-verify`, `deploy`.

```sh
make build && ./bin/tgproxy version
```

## Dev-окружение

Конфиги и фикстуры — в `dev/`. `dev/users.yml` содержит пользователя `admin` с паролем `dev-password` — **только для разработки**, в проде не использовать. Токен тестового бота — в `dev/.env` (шаблон `dev/.env.example`, не коммитится).
