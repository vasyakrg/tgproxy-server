-- +goose Up
-- Индексы под фильтры журнала ошибок (agent, bot_id, phase, code, request_id,
-- method, outcome) с сортировкой по id (курсор «новые первыми»). Индексы
-- (agent_id, id), (bot_id, id), (outcome, id) и (at) уже есть в 0001.
CREATE INDEX error_events_phase ON error_events (phase, id);
CREATE INDEX error_events_code ON error_events (code, id);
CREATE INDEX error_events_request ON error_events (request_id, id);
CREATE INDEX error_events_method ON error_events (method, id);

-- +goose Down
DROP INDEX error_events_method;
DROP INDEX error_events_request;
DROP INDEX error_events_code;
DROP INDEX error_events_phase;
