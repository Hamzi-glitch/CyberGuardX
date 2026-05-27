import json
import sqlite3
from datetime import datetime
from pathlib import Path

from risk_engine import RISK_ORDER, highest_risk


DB_PATH = Path(__file__).resolve().parent / "cyberguardx.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                max_risk TEXT NOT NULL,
                report_path TEXT,
                timeline_json TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                event_type TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT,
                tactic TEXT,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                summary TEXT NOT NULL,
                explanation TEXT NOT NULL,
                evidence TEXT NOT NULL,
                time_evidence TEXT,
                investigation_note TEXT,
                context_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                actions_json TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES incidents (id)
            )
            """
        )
        ensure_column(connection, "incidents", "timeline_json", "TEXT")
        ensure_column(connection, "findings", "time_evidence", "TEXT")


def ensure_column(connection, table_name, column_name, column_type):
    columns = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    if column_name not in {column["name"] for column in columns}:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


def save_incident(filename, findings):
    init_db()
    max_risk = highest_risk(findings)
    uploaded_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    timeline = build_timeline(findings)

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO incidents (filename, uploaded_at, total_findings, max_risk, report_path, timeline_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (filename, uploaded_at, len(findings), max_risk, None, json.dumps(timeline)),
        )
        incident_id = cursor.lastrowid

        for finding in findings:
            connection.execute(
                """
                INSERT INTO findings (
                    incident_id, title, event_type, line_number, source_ip, username,
                    tactic, risk_level, risk_score, summary, explanation, evidence,
                    time_evidence, investigation_note, context_json, metadata_json, actions_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    finding["title"],
                    finding["event_type"],
                    finding["line_number"],
                    finding.get("source_ip", "Unknown"),
                    finding.get("username", "Unknown"),
                    finding.get("tactic", ""),
                    finding["risk_level"],
                    finding["risk_score"],
                    finding["summary"],
                    finding["explanation"],
                    finding.get("evidence", ""),
                    finding.get("time_evidence", "Not available"),
                    finding.get("investigation_note", ""),
                    json.dumps(finding.get("context", [])),
                    json.dumps(finding.get("metadata", {})),
                    json.dumps(finding.get("recommended_actions", [])),
                ),
            )

    return incident_id


def update_report_path(incident_id, report_filename):
    with get_connection() as connection:
        connection.execute(
            "UPDATE incidents SET report_path = ? WHERE id = ?",
            (report_filename, incident_id),
        )


def get_incident(incident_id):
    init_db()
    with get_connection() as connection:
        incident_row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()

        if not incident_row:
            return None

        findings = connection.execute(
            "SELECT * FROM findings WHERE incident_id = ? ORDER BY risk_score DESC, line_number ASC",
            (incident_id,),
        ).fetchall()

    incident = dict(incident_row)
    incident["findings"] = [inflate_finding(row) for row in findings]
    incident["risk_counts"] = risk_counts_for_findings(incident["findings"])
    incident["timeline"] = json.loads(incident.get("timeline_json") or "[]")
    if not incident["timeline"]:
        incident["timeline"] = build_timeline(incident["findings"])
    return incident


def get_recent_incidents(limit=10):
    init_db()
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_risk_counts():
    init_db()
    counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT risk_level, COUNT(*) AS count FROM findings GROUP BY risk_level"
        ).fetchall()
    for row in rows:
        counts[row["risk_level"]] = row["count"]
    return counts


def inflate_finding(row):
    finding = dict(row)
    finding["context"] = json.loads(finding.pop("context_json") or "[]")
    finding["metadata"] = json.loads(finding.pop("metadata_json") or "{}")
    finding["recommended_actions"] = json.loads(finding.pop("actions_json") or "[]")
    finding["time_evidence"] = finding.get("time_evidence") or "Not available"
    return finding


def build_timeline(findings):
    timeline = []
    for finding in sorted(findings, key=lambda item: item.get("line_number", 0)):
        metadata = finding.get("metadata", {})
        timeline.append(
            {
                "line_number": finding.get("line_number"),
                "time_evidence": finding.get("time_evidence", "Not available"),
                "event_type": finding.get("event_type"),
                "title": finding.get("title"),
                "risk_level": finding.get("risk_level"),
                "source_ip": finding.get("source_ip", "Unknown"),
                "username": finding.get("username", "Unknown"),
                "failed_attempts": metadata.get("failed_attempts")
                or metadata.get("prior_failed_attempts")
                or 0,
                "success_after_failure": bool(metadata.get("success_after_failure", False)),
                "summary": finding.get("summary", ""),
                "evidence": finding.get("evidence", ""),
            }
        )
    return timeline


def risk_counts_for_findings(findings):
    counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for finding in findings:
        counts[finding["risk_level"]] += 1
    return counts


def sort_risks(risks):
    return sorted(risks, key=lambda risk: RISK_ORDER[risk], reverse=True)
