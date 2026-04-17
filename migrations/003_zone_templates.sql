CREATE TABLE zone_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    nameservers TEXT NOT NULL DEFAULT '[]',
    soa_mname TEXT NOT NULL DEFAULT '',
    soa_rname TEXT NOT NULL DEFAULT '',
    soa_refresh INTEGER NOT NULL DEFAULT 3600,
    soa_retry INTEGER NOT NULL DEFAULT 900,
    soa_expire INTEGER NOT NULL DEFAULT 604800,
    soa_ttl INTEGER NOT NULL DEFAULT 300,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
