CREATE TABLE zone_server_map_new (
    zone_name      TEXT    NOT NULL,
    pdns_server_id INTEGER NOT NULL REFERENCES pdns_servers(id) ON DELETE RESTRICT,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (zone_name, pdns_server_id)
);
INSERT INTO zone_server_map_new SELECT zone_name, pdns_server_id, created_at FROM zone_server_map;
DROP TABLE zone_server_map;
ALTER TABLE zone_server_map_new RENAME TO zone_server_map;
CREATE INDEX idx_zone_server_map_server ON zone_server_map(pdns_server_id);
