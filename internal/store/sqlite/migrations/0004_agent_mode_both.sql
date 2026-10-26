-- +goose Up
-- Режим связи агента both (dial + reverse): пересоздание таблицы с расширенным CHECK
-- (SQLite не умеет менять CHECK на месте). Версия реестра увеличивается, чтобы кэши перечитались.
CREATE TABLE agents_new (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    url        TEXT NOT NULL DEFAULT '',
    mode       TEXT NOT NULL CHECK (mode IN ('dial', 'reverse', 'both')),
    weight     INTEGER NOT NULL DEFAULT 100 CHECK (weight >= 0),
    draining   INTEGER NOT NULL DEFAULT 0 CHECK (draining IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
INSERT INTO agents_new (id, name, url, mode, weight, draining, created_at, updated_at)
    SELECT id, name, url, mode, weight, draining, created_at, updated_at FROM agents;
DROP TABLE agents;
ALTER TABLE agents_new RENAME TO agents;

-- +goose StatementBegin
CREATE TRIGGER agents_ver_ins AFTER INSERT ON agents
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'agents'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER agents_ver_upd AFTER UPDATE ON agents
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'agents'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER agents_ver_del AFTER DELETE ON agents
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'agents'; END;
-- +goose StatementEnd
UPDATE versions SET v = v + 1 WHERE name = 'agents';

-- +goose Down
UPDATE agents SET mode = 'dial' WHERE mode = 'both';
CREATE TABLE agents_old (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    url        TEXT NOT NULL DEFAULT '',
    mode       TEXT NOT NULL CHECK (mode IN ('dial', 'reverse')),
    weight     INTEGER NOT NULL DEFAULT 100 CHECK (weight >= 0),
    draining   INTEGER NOT NULL DEFAULT 0 CHECK (draining IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
INSERT INTO agents_old SELECT id, name, url, mode, weight, draining, created_at, updated_at FROM agents;
DROP TABLE agents;
ALTER TABLE agents_old RENAME TO agents;
-- +goose StatementBegin
CREATE TRIGGER agents_ver_ins AFTER INSERT ON agents
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'agents'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER agents_ver_upd AFTER UPDATE ON agents
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'agents'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER agents_ver_del AFTER DELETE ON agents
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'agents'; END;
-- +goose StatementEnd
