-- +goose Up
-- Токен перевыпуска для существующего агента: NULL — токен нового агента.
ALTER TABLE enrollments ADD COLUMN agent_id TEXT;

-- +goose Down
ALTER TABLE enrollments DROP COLUMN agent_id;
