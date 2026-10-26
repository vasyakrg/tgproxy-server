-- +goose Up
-- SSH-цель агента для аварийного обновления по SSH (M7). NULL — цель неизвестна.
ALTER TABLE agents ADD COLUMN ssh_host TEXT;
ALTER TABLE agents ADD COLUMN ssh_port INTEGER;

-- Заполнение для агентов, установленных установщиком: install_jobs.host = "host:port" ("[v6]:port").
UPDATE agents SET
    ssh_host = (SELECT trim(substr(j.host, 1, length(rtrim(j.host, '0123456789')) - 1), '[]')
                  FROM install_jobs j
                 WHERE j.agent_id = agents.id AND j.kind = 'install' AND j.state = 'done'
                 ORDER BY j.created_at DESC LIMIT 1),
    ssh_port = (SELECT CAST(substr(j.host, length(rtrim(j.host, '0123456789')) + 1) AS INTEGER)
                  FROM install_jobs j
                 WHERE j.agent_id = agents.id AND j.kind = 'install' AND j.state = 'done'
                 ORDER BY j.created_at DESC LIMIT 1)
 WHERE EXISTS (SELECT 1 FROM install_jobs j
                WHERE j.agent_id = agents.id AND j.kind = 'install' AND j.state = 'done'
                  AND j.host LIKE '%:%' AND length(rtrim(j.host, '0123456789')) < length(j.host));

-- +goose Down
ALTER TABLE agents DROP COLUMN ssh_port;
ALTER TABLE agents DROP COLUMN ssh_host;
