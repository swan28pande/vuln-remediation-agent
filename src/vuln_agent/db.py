"""PostgreSQL persistence: one row per alert the agent has handled."""

import psycopg

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS remediations (
    id           SERIAL PRIMARY KEY,
    repo         TEXT NOT NULL,
    alert_kind   TEXT NOT NULL,          -- 'dependabot' | 'code_scanning'
    alert_number INTEGER NOT NULL,
    vuln_id      TEXT,
    status       TEXT NOT NULL,          -- drafted | ci_failed | pr_opened | skipped | error
    branch       TEXT,
    pr_url       TEXT,
    detail       TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repo, alert_kind, alert_number)
);
"""


def connect() -> psycopg.Connection:
    conn = psycopg.connect(settings.database_url, autocommit=True)
    conn.execute(SCHEMA)
    return conn


def already_handled(conn, repo: str, kind: str, number: int) -> bool:
    row = conn.execute(
        "SELECT status FROM remediations WHERE repo=%s AND alert_kind=%s AND alert_number=%s",
        (repo, kind, number),
    ).fetchone()
    return row is not None and row[0] in ("pr_opened", "skipped")


def record(conn, repo: str, kind: str, number: int, status: str, **fields) -> None:
    conn.execute(
        """
        INSERT INTO remediations (repo, alert_kind, alert_number, vuln_id, status, branch, pr_url, detail)
        VALUES (%(repo)s, %(kind)s, %(number)s, %(vuln_id)s, %(status)s, %(branch)s, %(pr_url)s, %(detail)s)
        ON CONFLICT (repo, alert_kind, alert_number) DO UPDATE SET
            vuln_id = EXCLUDED.vuln_id, status = EXCLUDED.status, branch = EXCLUDED.branch,
            pr_url = EXCLUDED.pr_url, detail = EXCLUDED.detail, updated_at = now()
        """,
        {
            "repo": repo, "kind": kind, "number": number, "status": status,
            "vuln_id": fields.get("vuln_id"), "branch": fields.get("branch"),
            "pr_url": fields.get("pr_url"), "detail": fields.get("detail"),
        },
    )
