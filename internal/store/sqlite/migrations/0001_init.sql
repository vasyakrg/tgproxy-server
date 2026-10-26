-- +goose Up
-- Все времена — INTEGER unix milliseconds (UTC).

-- Монотонные счётчики изменений для инвалидации кэшей (растут триггерами,
-- поэтому видны и при записи из другого процесса, например CLI).
CREATE TABLE versions (
    name TEXT PRIMARY KEY,
    v    INTEGER NOT NULL
) WITHOUT ROWID;
INSERT INTO versions (name, v) VALUES ('agents', 1), ('access_rules', 1);

CREATE TABLE agents (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    url        TEXT NOT NULL DEFAULT '',
    mode       TEXT NOT NULL CHECK (mode IN ('dial', 'reverse')),
    weight     INTEGER NOT NULL DEFAULT 100 CHECK (weight >= 0),
    draining   INTEGER NOT NULL DEFAULT 0 CHECK (draining IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

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

-- host = "host:port" (пин создаётся в мастере до появления агента).
CREATE TABLE agent_hostkeys (
    host        TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL DEFAULT '',
    algo        TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    public_key  BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX agent_hostkeys_agent ON agent_hostkeys (agent_id);

-- История сертификатов переживает удаление агента (аудит, denylist).
CREATE TABLE certs (
    serial     TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    subject    TEXT NOT NULL DEFAULT '',
    not_before INTEGER NOT NULL,
    not_after  INTEGER NOT NULL,
    cert_pem   BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX certs_agent ON certs (agent_id, not_after);
CREATE INDEX certs_not_after ON certs (not_after);

CREATE TABLE cert_denylist (
    serial    TEXT PRIMARY KEY,
    agent_id  TEXT NOT NULL DEFAULT '',
    reason    TEXT NOT NULL DEFAULT '',
    not_after INTEGER NOT NULL,
    denied_at INTEGER NOT NULL
);
CREATE INDEX cert_denylist_not_after ON cert_denylist (not_after);

-- Единственная строка: CA проекта (ключ зашифрован KEK).
CREATE TABLE pki_ca (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    cert_pem   BLOB NOT NULL,
    sealed_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE access_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    cidrs      TEXT NOT NULL DEFAULT '[]'
               CHECK (json_valid(cidrs) AND json_type(cidrs) = 'array'),
    key_hash   BLOB CHECK (key_hash IS NULL OR length(key_hash) = 32),
    key_prefix TEXT NOT NULL DEFAULT '',
    rps        REAL NOT NULL DEFAULT 0 CHECK (rps >= 0),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    -- правило без сети и без ключа = открытый relay к Bot API
    CHECK (json_array_length(cidrs) > 0 OR key_hash IS NOT NULL)
);
CREATE UNIQUE INDEX access_rules_key_hash ON access_rules (key_hash) WHERE key_hash IS NOT NULL;

-- +goose StatementBegin
CREATE TRIGGER access_rules_ver_ins AFTER INSERT ON access_rules
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'access_rules'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER access_rules_ver_upd AFTER UPDATE ON access_rules
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'access_rules'; END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER access_rules_ver_del AFTER DELETE ON access_rules
BEGIN UPDATE versions SET v = v + 1 WHERE name = 'access_rules'; END;
-- +goose StatementEnd

-- id = SHA-256 cookie-токена.
CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    user            TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('pending', 'full')),
    ip              TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions (user);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE rate_windows (
    key        TEXT PRIMARY KEY,
    value      BLOB NOT NULL,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX rate_windows_expires ON rate_windows (expires_at);

CREATE TABLE outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key  TEXT NOT NULL,
    agent_id   TEXT NOT NULL DEFAULT '',
    type       TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('firing', 'resolved')),
    text       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    sent_at    INTEGER,
    attempts   INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX outbox_pending ON outbox (id) WHERE sent_at IS NULL;
CREATE INDEX outbox_dedup ON outbox (dedup_key, id);
CREATE INDEX outbox_sent ON outbox (sent_at) WHERE sent_at IS NOT NULL;

CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    ip     TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at ON audit_log (at);
CREATE INDEX audit_log_actor ON audit_log (actor, id);

CREATE TABLE samples_10s (
    agent_id     TEXT NOT NULL,
    ts           INTEGER NOT NULL,
    ok           INTEGER NOT NULL DEFAULT 0,
    err          INTEGER NOT NULL DEFAULT 0,
    rate_limited INTEGER NOT NULL DEFAULT 0,
    p95_ms       REAL NOT NULL DEFAULT 0,
    inflight     INTEGER NOT NULL DEFAULT 0,
    buckets      TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (agent_id, ts)
) WITHOUT ROWID;
CREATE INDEX samples_10s_ts ON samples_10s (ts);

CREATE TABLE samples_5m (
    agent_id     TEXT NOT NULL,
    ts           INTEGER NOT NULL,
    ok           INTEGER NOT NULL DEFAULT 0,
    err          INTEGER NOT NULL DEFAULT 0,
    rate_limited INTEGER NOT NULL DEFAULT 0,
    p95_ms       REAL NOT NULL DEFAULT 0,
    inflight     INTEGER NOT NULL DEFAULT 0,
    buckets      TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (agent_id, ts)
) WITHOUT ROWID;
CREATE INDEX samples_5m_ts ON samples_5m (ts);

CREATE TABLE error_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,
    request_id  TEXT NOT NULL DEFAULT '',
    bot_id      TEXT NOT NULL DEFAULT '',
    agent_id    TEXT NOT NULL DEFAULT '',
    method      TEXT NOT NULL DEFAULT '',
    phase       TEXT NOT NULL DEFAULT '',
    code        INTEGER NOT NULL DEFAULT 0,
    outcome     TEXT NOT NULL CHECK (outcome IN ('retried', 'failed_to_bot', 'passed_to_bot')),
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX error_events_at ON error_events (at);
CREATE INDEX error_events_agent ON error_events (agent_id, id);
CREATE INDEX error_events_bot ON error_events (bot_id, id);
CREATE INDEX error_events_outcome ON error_events (outcome, id);

-- token_hash = SHA-256 токена; сам токен не хранится.
CREATE TABLE enrollments (
    id         TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    name       TEXT NOT NULL,
    weight     INTEGER NOT NULL DEFAULT 100 CHECK (weight >= 0),
    created_by TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE INDEX enrollments_expires ON enrollments (expires_at);

-- Задачи SSH-установщика (M5): креды админа в БД не пишутся.
CREATE TABLE install_jobs (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL DEFAULT '',
    host        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    state       TEXT NOT NULL,
    error       TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    finished_at INTEGER
);
CREATE INDEX install_jobs_created ON install_jobs (created_at);

CREATE TABLE install_job_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id  TEXT NOT NULL REFERENCES install_jobs (id) ON DELETE CASCADE,
    at      INTEGER NOT NULL,
    step    TEXT NOT NULL DEFAULT '',
    level   TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX install_job_events_job ON install_job_events (job_id, id);

-- Установленные/доступные релизы (M6).
CREATE TABLE releases (
    version      TEXT PRIMARY KEY,
    channel      TEXT NOT NULL DEFAULT 'stable',
    checksum     TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT '',
    discovered_at INTEGER NOT NULL,
    installed_at INTEGER
);

-- +goose Down
DROP TABLE releases;
DROP TABLE install_job_events;
DROP TABLE install_jobs;
DROP TABLE enrollments;
DROP TABLE error_events;
DROP TABLE samples_5m;
DROP TABLE samples_10s;
DROP TABLE audit_log;
DROP TABLE outbox;
DROP TABLE rate_windows;
DROP TABLE sessions;
DROP TABLE access_rules;
DROP TABLE pki_ca;
DROP TABLE cert_denylist;
DROP TABLE certs;
DROP TABLE agent_hostkeys;
DROP TABLE agents;
DROP TABLE versions;
