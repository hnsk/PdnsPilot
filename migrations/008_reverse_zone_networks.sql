CREATE TABLE IF NOT EXISTS reverse_zone_networks (
    zone_name  TEXT NOT NULL PRIMARY KEY,
    network    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
