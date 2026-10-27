-- +goose Up
-- MTProto-прокси: секреты клиентов и журнал соединений (docs/mtproto.md §11).

-- secret_enc — непрозрачные байты (шифрует сервисный слой KEK с aad "mtproto/<id>").
-- prefix — первые 4 байта ключа в hex, для UI/логов. cidrs — JSON-массив или NULL.
-- max_conns = 0 — без лимита. grace_until: пока не истёк, ротированный/отозванный секрет ещё принимается.
CREATE TABLE mtproto_secrets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    secret_enc   BLOB NOT NULL,
    prefix       TEXT NOT NULL,
    cidrs        TEXT,
    max_conns    INTEGER NOT NULL DEFAULT 0 CHECK (max_conns >= 0),
    enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    grace_until  INTEGER,
    rotated_from INTEGER REFERENCES mtproto_secrets (id)
);

INSERT INTO versions (name, v) VALUES ('mtproto_secrets', 1);

-- +goose StatementBegin
CREATE TRIGGER mtproto_secrets_ver_ins AFTER INSERT ON mtproto_secrets
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'mtproto_secrets'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER mtproto_secrets_ver_upd AFTER UPDATE ON mtproto_secrets
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'mtproto_secrets'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER mtproto_secrets_ver_del AFTER DELETE ON mtproto_secrets
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'mtproto_secrets'; END;
-- +goose StatementEnd

-- Журнал соединений (retention как у error_events); без FK, чтобы не терять историю.
CREATE TABLE mtproto_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER NOT NULL,
    client_ip    TEXT NOT NULL DEFAULT '',
    secret_id    INTEGER NOT NULL,
    dc           INTEGER NOT NULL DEFAULT 0,
    agent_id     TEXT NOT NULL DEFAULT '',
    bytes_in     INTEGER NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    bytes_out    INTEGER NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    close_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX mtproto_sessions_ended ON mtproto_sessions (ended_at);
CREATE INDEX mtproto_sessions_secret ON mtproto_sessions (secret_id, id);

-- +goose Down
DROP INDEX mtproto_sessions_secret;
DROP INDEX mtproto_sessions_ended;
DROP TABLE mtproto_sessions;
DROP TRIGGER mtproto_secrets_ver_del;
DROP TRIGGER mtproto_secrets_ver_upd;
DROP TRIGGER mtproto_secrets_ver_ins;
DELETE FROM versions WHERE name = 'mtproto_secrets';
DROP TABLE mtproto_secrets;
