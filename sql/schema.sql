PRAGMA foreign_keys = ON;


CREATE TABLE IF NOT EXISTS events (
id INTEGER PRIMARY KEY AUTOINCREMENT,
ts TEXT NOT NULL,
host TEXT,
src_ip TEXT,
dst_ip TEXT,
username TEXT,
event_type TEXT,
user_agent TEXT,
message TEXT,
country TEXT,
region TEXT,
city TEXT
);


CREATE TABLE IF NOT EXISTS alerts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
event_id INTEGER,
alert_type TEXT,
alert_score INTEGER,
details TEXT,
created_at TEXT DEFAULT (datetime('now')),
FOREIGN KEY(event_id) REFERENCES events(id)
);