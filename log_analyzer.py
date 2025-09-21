import pandas as pd
import sqlite3
import re
from pathlib import Path

# ----------------------
# Paths & config
# ----------------------
DATA_FILE = Path(__file__).parent / "data/sample_logs.csv"
DB_FILE = Path(__file__).parent / "cyber_logs.db"
CSV_EXPORT = Path(__file__).parent / "exported_alerts.csv"
JSON_EXPORT = Path(__file__).parent / "exported_alerts.json"
REGEX_FILE = Path(__file__).parent / "config/regex_patterns.md"

# ----------------------
# Load logs
# ----------------------
df = pd.read_csv(DATA_FILE)

# ----------------------
# Load regex patterns
# ----------------------
patterns = {}
with open(REGEX_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, val = line.split("=", 1)
            patterns[key.strip()] = val.strip()

# ----------------------
# Initialize DB
# ----------------------
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

# ----------------------
# Detect failed login spikes
# ----------------------
failed = df[df["event_type"] == "login_failure"]
failed_counts = failed.groupby("src_ip").size()

for ip, count in failed_counts.items():
    if count >= 3:
        print(f"[ALERT] Failed login spike from {ip} ({count} attempts)")
        c.execute("INSERT INTO alerts (alert_type, src_ip, username, message) VALUES (?,?,?,?)",
                  ("failed_login_spike", ip, "", f"{count} failed login attempts"))

# ----------------------
# Detect suspicious user agents
# ----------------------
suspicious_pattern = re.compile(patterns.get("SUSPICIOUS_UA", ""), re.IGNORECASE)
for _, row in df.iterrows():
    ua = row["user_agent"]
    if suspicious_pattern.search(ua):
        print(f"[ALERT] Suspicious user agent '{ua}' from {row['src_ip']}")
        c.execute("INSERT INTO alerts (alert_type, src_ip, username, message) VALUES (?,?,?,?)",
                  ("suspicious_ua", row["src_ip"], row["username"], ua))

conn.commit()

# ----------------------
# Export alerts for Power BI
# ----------------------
alerts_df = pd.read_sql_query("SELECT * FROM alerts", conn)
alerts_df.to_csv(CSV_EXPORT, index=False)
alerts_df.to_json(JSON_EXPORT, orient="records", lines=True)

conn.close()

print("\n✅ Analysis complete. Alerts saved to cyber_logs.db, exported to CSV and JSON!")
