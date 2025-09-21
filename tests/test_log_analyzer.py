import os
import json
import sqlite3
import pandas as pd
import pytest

import log_analyzer as la

SAMPLE_CSV = """timestamp,host,src_ip,dst_ip,username,event_type,user_agent,message
2025-09-20T08:12:34Z,web01,203.0.113.5,10.0.0.5,alice,login_success,"Mozilla/5.0 (Windows NT 10.0; Win64; x64)","Successful login"
2025-09-20T08:15:12Z,web01,198.51.100.23,10.0.0.5,bob,login_failure,"curl/7.68.0","Invalid password"
2025-09-20T08:16:45Z,web01,198.51.100.23,10.0.0.5,bob,login_failure,"curl/7.68.0","Invalid password"
2025-09-20T08:17:11Z,web01,198.51.100.23,10.0.0.5,bob,login_failure,"curl/7.68.0","Invalid password"
2025-09-20T20:20:01Z,web02,45.77.23.88,10.0.1.3,carol,login_success,"Mozilla/5.0 (Linux; Android 10)","Successful login"
2025-09-21T03:02:00Z,web03,203.0.113.5,10.0.2.8,alice,login_success,"Mozilla/5.0 (Macintosh)","Successful login from new country"
"""

def _write_sample(tmp_path):
    p = tmp_path / "sample_logs.csv"
    p.write_text(SAMPLE_CSV)
    return str(p)

def test_run_creates_db_and_events(tmp_path, monkeypatch):
    """Run the main analyzer and check DB + events created."""
    sample_path = _write_sample(tmp_path)

    db_path = tmp_path / "test_cyber.db"
    # ensure the analyzer uses our temp DB
    monkeypatch.setenv("CYBER_DB", str(db_path))

    # run analyzer (this will init DB, persist events, generate alerts, export for PowerBI)
    la.run(sample_path)

    assert db_path.exists(), "Database file was not created."

    # verify events table has rows
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    count = cur.fetchone()[0]
    conn.close()
    assert count > 0, "No events were inserted into the DB."

def test_detection_functions(tmp_path):
    """Test detection helpers on sample data (failed login spike & suspicious UA)."""
    sample_path = _write_sample(tmp_path)
    df = la.load_logs(sample_path)

    # failed login spike detection (we expect IP 198.51.100.23 to trigger)
    failed_alerts = la.detect_failed_login_spikes(df)
    assert any(a.get("src_ip") == "198.51.100.23" and a.get("type") == "failed_login_spike" for a in failed_alerts), \
        "Failed login spike for 198.51.100.23 not detected."

    # suspicious user-agent detection (curl should be detected)
    ua_alerts = la.detect_suspicious_user_agents(df)
    assert any("curl" in (a.get("ua") or "").lower() for a in ua_alerts), "Suspicious 'curl' user-agent not detected."

def test_export_for_powerbi_creates_json(tmp_path):
    """Test exporting events to JSON for Power BI."""
    sample_path = _write_sample(tmp_path)

    # init DB in tmp and persist events directly (avoid calling run which also writes to repo powerbi/)
    db_path = tmp_path / "export.db"
    conn = la.init_db(db_path=str(db_path))
    df = la.load_logs(sample_path)
    la.persist_events(conn, df)

    out_json = tmp_path / "events_export.json"
    la.export_for_powerbi(conn, out_json=str(out_json))

    assert out_json.exists(), "Power BI export JSON was not created."
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == len(df), "Exported JSON does not match expected event count."

    conn.close()
