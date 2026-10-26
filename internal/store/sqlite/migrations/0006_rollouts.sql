-- +goose Up
-- Раскатки версий на агентов (M6-T4). agent_id без FK: история переживает удаление агента.
CREATE TABLE rollouts (
    id             TEXT PRIMARY KEY,
    version        TEXT NOT NULL,
    batch_size     INTEGER NOT NULL,
    canary         INTEGER NOT NULL,
    allow_downtime INTEGER NOT NULL DEFAULT 0,
    state          TEXT NOT NULL,
    error          TEXT NOT NULL DEFAULT '',
    actor          TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL,
    finished_at    INTEGER
);
CREATE INDEX rollouts_created ON rollouts (created_at);

CREATE TABLE rollout_steps (
    rollout_id   TEXT NOT NULL REFERENCES rollouts(id) ON DELETE CASCADE,
    agent_id     TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    phase        TEXT NOT NULL,
    state        TEXT NOT NULL,
    from_version TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (rollout_id, agent_id)
);

-- +goose Down
DROP TABLE rollout_steps;
DROP TABLE rollouts;
