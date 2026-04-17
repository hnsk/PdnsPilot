CREATE TABLE pdns_servers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    api_url    TEXT    NOT NULL,
    api_key    TEXT    NOT NULL,
    server_id  TEXT    NOT NULL DEFAULT 'localhost',
    is_active  INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE zone_server_map (
    zone_name      TEXT    NOT NULL PRIMARY KEY,
    pdns_server_id INTEGER NOT NULL REFERENCES pdns_servers(id) ON DELETE RESTRICT,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_zone_server_map_server ON zone_server_map(pdns_server_id);
