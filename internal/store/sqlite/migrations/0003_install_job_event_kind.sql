-- +goose Up
-- Тип события установки (step/log/done/error) для SSE мастера «Новый агент».
ALTER TABLE install_job_events ADD COLUMN kind TEXT NOT NULL DEFAULT 'log';

-- +goose Down
ALTER TABLE install_job_events DROP COLUMN kind;
