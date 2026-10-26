"""Apply pending incident-store migrations.

A fresh Docker volume gets the whole schema from infra/schema.sql via
docker-entrypoint-initdb.d. That path does not help an *existing* volume --
init scripts only run on first boot -- so changes also land here as numbered
files, and this applies the ones not yet recorded.

    .venv-app\\Scripts\\python scripts/migrate_store.py          # apply pending
    .venv-app\\Scripts\\python scripts/migrate_store.py --status # just report
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg

from shared.llm import load_project_env
from shared.store import store_dsn

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "infra" / "migrations"

TRACKING_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename    TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def main() -> int:
    load_project_env()
    report_only = "--status" in sys.argv

    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        print(f"[migrate] no migrations in {MIGRATIONS_DIR}")
        return 0

    dsn = store_dsn()
    print(f"[migrate] dsn = {dsn}")

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(TRACKING_TABLE)
        applied = {r[0] for r in conn.execute("SELECT filename FROM schema_migrations").fetchall()}

        pending = [f for f in files if f.name not in applied]
        for f in files:
            mark = "applied" if f.name in applied else "PENDING"
            print(f"[migrate] {mark:8s} {f.name}")

        if report_only:
            print(f"\n[migrate] {len(pending)} pending")
            return 0

        if not pending:
            print("\n[migrate] nothing to do")
            return 0

        for f in pending:
            print(f"\n[migrate] applying {f.name} ...")
            sql = f.read_text(encoding="utf-8")
            try:
                # The file manages its own BEGIN/COMMIT so a partial migration
                # cannot leave the table half-constrained.
                conn.execute(sql)
                conn.execute(
                    "INSERT INTO schema_migrations (filename) VALUES (%s) "
                    "ON CONFLICT (filename) DO NOTHING",
                    (f.name,),
                )
            except Exception as exc:  # noqa: BLE001
                print(f"[migrate] FAILED on {f.name}: {exc}")
                return 1
            print(f"[migrate] ok {f.name}")

    print(f"\n[migrate] applied {len(pending)} migration(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
