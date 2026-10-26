// Package rollout — раскатка версии агентов (architecture §12, plan M6-T4).
//
// Отдельный пакет, а не файл installer: installer — SSH-мастер с кредами админа и
// своей машиной шагов/откатов, раскатка же работает только по уже открытому mTLS-каналу
// (dial и reverse одинаково через transport.AgentTransport), без SSH и кредов.
//
// Порядок: канарейка (по умолчанию 1 агент) → батчи по BatchSize. На каждом агенте:
// drain → ожидание inflight → POST /_agent/update {version, gateway_url} (агент сам
// качает релиз с agent_gateway, проверяет minisign встроенными ключами и min_version,
// кладёт в updates/staged; root-oneshot ставит и откатывает на prev.deb) → ожидание
// «агент вернулся на целевой версии» → undrain. Провал канарейки — остальные агенты
// не трогаются; провал в батче — раскатка останавливается, агент откатывается сам
// (apply), админам уходит алерт rollout_failed. Состояние хранится в БД
// (rollouts, rollout_steps) и переживает рестарт сервера.
package rollout
