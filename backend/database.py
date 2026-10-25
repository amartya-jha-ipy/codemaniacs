import sqlite3
import os
from datetime import datetime

DB_PATH = "database/sentinel_audit.db"

def init_db():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            case_id TEXT,
            filename TEXT,
            sha256 TEXT,
            risk_score INTEGER,
            classification TEXT,
            uploader_role TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_analysis(case_id: str, filename: str, sha256: str, risk_score: int, classification: str, role: str):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO audit_logs (timestamp, case_id, filename, sha256, risk_score, classification, uploader_role)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, case_id, filename, sha256, risk_score, classification, role))
    conn.commit()
    conn.close()