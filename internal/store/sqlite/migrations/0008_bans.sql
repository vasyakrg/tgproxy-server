-- +goose Up
-- Баны IP (встроенный fail2ban), отказы доступа в журнале ошибок и графике «Обзор».

-- prefix: IPv4 /32 ("1.2.3.4/32") или IPv6 /64 ("2001:db8::/64"); одна запись на префикс.
-- expires_at NULL — бессрочно. level — уровень эскалации автобана; last_hit_at — последняя
-- активность (создание/попадание), от неё считается сброс эскалации.
CREATE TABLE bans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix      TEXT NOT NULL UNIQUE,
    source      TEXT NOT NULL CHECK (source IN ('auto', 'manual')),
    actor       TEXT NOT NULL DEFAULT '',
    comment     TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    hits        INTEGER NOT NULL DEFAULT 0 CHECK (hits >= 0),
    level       INTEGER NOT NULL DEFAULT 0 CHECK (level >= 0),
    last_hit_at INTEGER NOT NULL
);
CREATE INDEX bans_expires ON bans (expires_at);

INSERT INTO versions (name, v) VALUES ('bans', 1);

-- +goose StatementBegin
CREATE TRIGGER bans_ver_ins AFTER INSERT ON bans
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'bans'; END;
-- +goose StatementEnd
-- Счётчик попаданий (hits, last_hit_at) версию не двигает: иначе кэш сбрасывался бы при каждом сбросе счётчиков.
-- +goose StatementBegin
CREATE TRIGGER bans_ver_upd AFTER UPDATE OF prefix, source, expires_at, created_at ON bans
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'bans'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER bans_ver_del AFTER DELETE ON bans
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'bans'; END;
-- +goose StatementEnd

-- Отказы доступа: реальный IP клиента и причина (фаза access).
ALTER TABLE error_events ADD COLUMN client_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE error_events ADD COLUMN reason TEXT NOT NULL DEFAULT '';
CREATE INDEX error_events_reason ON error_events (reason, id);
CREATE INDEX error_events_client_ip ON error_events (client_ip, id);

-- Отказы по причинам в окне: JSON {"no_rule":3,...}; пусто — отказов не было.
ALTER TABLE samples_10s ADD COLUMN denied TEXT NOT NULL DEFAULT '';
ALTER TABLE samples_5m ADD COLUMN denied TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE samples_5m DROP COLUMN denied;
ALTER TABLE samples_10s DROP COLUMN denied;
DROP INDEX error_events_client_ip;
DROP INDEX error_events_reason;
ALTER TABLE error_events DROP COLUMN reason;
ALTER TABLE error_events DROP COLUMN client_ip;
DROP TRIGGER bans_ver_del;
DROP TRIGGER bans_ver_upd;
DROP TRIGGER bans_ver_ins;
DELETE FROM versions WHERE name = 'bans';
DROP TABLE bans;
