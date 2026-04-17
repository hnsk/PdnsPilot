-- Add pdns_server_id to zone_assignments for server-specific access control.
-- Recreate table to drop old UNIQUE(user_id, zone_name) and replace with
-- UNIQUE(user_id, zone_name, pdns_server_id).

CREATE TABLE zone_assignments_new (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    zone_name      TEXT    NOT NULL,
    pdns_server_id INTEGER REFERENCES pdns_servers(id) ON DELETE CASCADE,
    UNIQUE(user_id, zone_name, pdns_server_id)
);

-- Backfill: pick first server from zone_server_map for each existing assignment.
INSERT INTO zone_assignments_new (user_id, zone_name, pdns_server_id)
SELECT za.user_id, za.zone_name,
       (SELECT m.pdns_server_id FROM zone_server_map m WHERE m.zone_name = za.zone_name LIMIT 1)
FROM zone_assignments za;

DROP TABLE zone_assignments;
ALTER TABLE zone_assignments_new RENAME TO zone_assignments;

CREATE INDEX idx_zone_assignments_user ON zone_assignments(user_id);
CREATE INDEX idx_zone_assignments_zone ON zone_assignments(zone_name);
