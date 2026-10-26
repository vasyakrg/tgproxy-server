# Релиз

Релиз собирается workflow `.github/workflows/release.yml` по тегу `v*`.
Порядок: тесты -> goreleaser (`--skip=publish`, подпись `checksums.txt`) -> проверка подписи
и sha256 -> smoke deb в debian:12 -> публикация в GitHub Releases (`gh release create`).

## Ключ minisign (ОВ-4)

```sh
minisign -G -p packaging/minisign.pub -s tgproxy-release.key   # задать пароль
```

- Публичный `packaging/minisign.pub` коммитится; он же вшивается в `update.pubkeys`.
- Приватный `tgproxy-release.key` НЕ коммитится. Хранить офлайн (менеджер паролей/сейф) + в секрете
  environment `release`. Пароль — отдельно.
- Пока в `packaging/minisign.pub` заглушка, release.yml падает с понятной ошибкой.

### Ротация

Сгенерировать второй ключ, добавить его публичную часть вторым элементом `update.pubkeys`
(допустимы 2 ключа), выпустить релиз, подписанный старым ключом, затем переключить секрет
`MINISIGN_SECRET_KEY` на новый и убрать старый публичный ключ в следующем релизе.

## Environment `release`

GitHub -> Settings -> Environments -> New environment `release`:

- Required reviewers: владелец(ы) релизов.
- Deployment branches and tags: только теги `v*`.
- Secrets: `MINISIGN_SECRET_KEY` (содержимое файла приватного ключа целиком), `MINISIGN_PASSWORD`.

Секреты доступны только после аппрува ревьюера; ключ пишется в `$RUNNER_TEMP` с правами 0600 и
удаляется в `always()`-шаге. Пароль передаётся minisign через stdin.

## Выпуск

```sh
git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
```

Затем подтвердить деплой в environment `release` на странице запуска workflow.
Локальный прогон без подписи/публикации: `make release-dry` (нужен docker).
