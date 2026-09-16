"""Export a scan report.

TEMPORARY — opened only to verify that SecureOS reviews pull requests end to
end. Delete this branch once the review has been confirmed.
"""
import os
import sqlite3
import subprocess

from flask import Blueprint, request, send_file

bp = Blueprint("report_export", __name__)


@bp.route("/api/reports/export")
def export_report():
    """Render a scan report to PDF and return it."""
    scan_id = request.args.get("scan_id", "")
    fmt = request.args.get("format", "pdf")

    # The scan id goes straight into a shell string.
    out = f"/tmp/report-{scan_id}.{fmt}"
    subprocess.run(
        f"wkhtmltopdf /var/reports/{scan_id}.html {out}",
        shell=True, check=True,
    )
    return send_file(out)


@bp.route("/api/reports/search")
def search_reports():
    """Find reports whose title matches a query."""
    q = request.args.get("q", "")
    db = sqlite3.connect(os.environ["REPORTS_DB"])
    # The query is concatenated into SQL.
    rows = db.execute(
        "SELECT id, title FROM reports WHERE title LIKE '%" + q + "%'"
    ).fetchall()
    return {"results": [{"id": r[0], "title": r[1]} for r in rows]}
