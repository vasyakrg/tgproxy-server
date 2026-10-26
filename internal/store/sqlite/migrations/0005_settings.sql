-- +goose Up
-- Настройки, меняемые из UI (переключатели уведомлений и т.п.).
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE settings;
