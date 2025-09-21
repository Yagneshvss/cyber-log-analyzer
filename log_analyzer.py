import pandas as pd
import sqlite3
from pathlib import Path
import re

# Config paths
DATA_FILE = Path(__file__).parent / "data/sample_logs.csv"
DB_FILE = Path(__file__).parent / "cyber_logs.db"
REGEX_FILE = Path(__file__).parent / "config/regex_patterns.md"

# Load CSV logs
df = pd.read_csv(DATA_FILE)

# Load regex patterns
patterns = {}
with open(REGEX_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, val = line.split("=", 1)
            patterns[key.strip()] = val.strip()

# Initialize DB
conn = sqlite3.connect(DB_FILE)
c = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT,
    src_ip TEXT,
    username TEXT,
    message TEXT
)
""")
conn.commit()

# 1️⃣ Detect failed login spikes (3+ from same IP)
failed = df[df["event_type"] == "login_failure"]
failed_counts = failed.groupby("src_ip").size()
for ip, count in failed_counts.items():
    if count >= 3:
        print(f"[ALERT] Failed login spike from {ip} ({count} attempts)")
        c.execute("INSERT INTO alerts (alert_type, src_ip, username, message) VALUES (?,?,?,?)",
                  ("failed_login_spike", ip, "", f"{count} failed login attempts"))

# 2️⃣ Detect suspicious user agents
suspicious_pattern = re.compile(patterns.get("SUSPICIOUS_UA", ""), re.IGNORECASE)
for _, row in df.iterrows():
    ua = row["user_agent"]
    if suspicious_pattern.search(ua):
        print(f"[ALERT] Suspicious user agent '{ua}' from {row['src_ip']}")
        c.execute("INSERT INTO alerts (alert_type, src_ip, username, message) VALUES (?,?,?,?)",
                  ("suspicious_ua", row["src_ip"], row["username"], ua))

conn.commit()
conn.close()

print("\n✅ Analysis complete. Alerts saved to cyber_logs.db")
