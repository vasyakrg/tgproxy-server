-- +goose Up
-- Ряды MTProto в истории: активные соединения (максимум за окно) и байты за окно.
-- Заполняются только у строки-агрегата.
ALTER TABLE samples_10s ADD COLUMN mtproto_conns INTEGER NOT NULL DEFAULT 0;
ALTER TABLE samples_10s ADD COLUMN mtproto_bytes_in INTEGER NOT NULL DEFAULT 0;
ALTER TABLE samples_10s ADD COLUMN mtproto_bytes_out INTEGER NOT NULL DEFAULT 0;
ALTER TABLE samples_5m ADD COLUMN mtproto_conns INTEGER NOT NULL DEFAULT 0;
ALTER TABLE samples_5m ADD COLUMN mtproto_bytes_in INTEGER NOT NULL DEFAULT 0;
ALTER TABLE samples_5m ADD COLUMN mtproto_bytes_out INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE samples_5m DROP COLUMN mtproto_bytes_out;
ALTER TABLE samples_5m DROP COLUMN mtproto_bytes_in;
ALTER TABLE samples_5m DROP COLUMN mtproto_conns;
ALTER TABLE samples_10s DROP COLUMN mtproto_bytes_out;
ALTER TABLE samples_10s DROP COLUMN mtproto_bytes_in;
ALTER TABLE samples_10s DROP COLUMN mtproto_conns;
