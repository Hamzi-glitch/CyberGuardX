import os
from pathlib import Path
from uuid import uuid4

from flask import Flask, abort, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from database import (
    get_incident,
    get_recent_incidents,
    get_risk_counts,
    init_db,
    save_incident,
    update_report_path,
)
from detector import detect_events
from explanation_agent import add_explanations
from investigator import investigate
from report_generator import generate_report
from risk_engine import score_findings


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
ALLOWED_EXTENSIONS = {".log", ".txt"}


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("CYBERGUARDX_SECRET_KEY", "development-only-secret-key")
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def read_log_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as log_file:
        return log_file.readlines()


def analyze_file(path, original_filename):
    lines = read_log_lines(path)
    events = detect_events(lines)
    findings = investigate(events, lines)
    scored_findings = score_findings(findings)
    explained_findings = add_explanations(scored_findings)

    incident_id = save_incident(original_filename, explained_findings)
    incident = get_incident(incident_id)
    report_filename = generate_report(
        incident=incident,
        output_dir=REPORT_DIR,
        template_dir=BASE_DIR / "templates",
        css_url="../static/style.css",
    )
    update_report_path(incident_id, report_filename)
    return incident_id


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        uploaded_file = request.files.get("log_file")
        if not uploaded_file or uploaded_file.filename == "":
            flash("Choose a .log or .txt file to analyze.", "error")
            return redirect(url_for("index"))

        if not allowed_file(uploaded_file.filename):
            flash("Only .log and .txt files are supported.", "error")
            return redirect(url_for("index"))

        safe_name = secure_filename(uploaded_file.filename)
        stored_name = f"{uuid4().hex}_{safe_name}"
        upload_path = UPLOAD_DIR / stored_name
        uploaded_file.save(upload_path)

        incident_id = analyze_file(upload_path, safe_name)
        flash("Log analysis complete.", "success")
        return redirect(url_for("dashboard", incident_id=incident_id))

    return render_template(
        "index.html",
        recent_incidents=get_recent_incidents(limit=6),
        risk_counts=get_risk_counts(),
    )


@app.route("/dashboard")
def dashboard_latest():
    incidents = get_recent_incidents(limit=1)
    if not incidents:
        return redirect(url_for("index"))
    return redirect(url_for("dashboard", incident_id=incidents[0]["id"]))


@app.route("/dashboard/<int:incident_id>")
def dashboard(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        abort(404)

    return render_template(
        "dashboard.html",
        incident=incident,
        recent_incidents=get_recent_incidents(limit=10),
        risk_counts=get_risk_counts(),
    )


@app.route("/report/<int:incident_id>")
def report(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        abort(404)

    if not incident.get("report_path"):
        report_filename = generate_report(
            incident=incident,
            output_dir=REPORT_DIR,
            template_dir=BASE_DIR / "templates",
            css_url=url_for("static", filename="style.css"),
        )
        update_report_path(incident_id, report_filename)
        incident = get_incident(incident_id)

    return render_template(
        "report.html",
        incident=incident,
        css_url=url_for("static", filename="style.css"),
        generated=True,
    )


@app.errorhandler(404)
def not_found(_error):
    return render_template("index.html", recent_incidents=get_recent_incidents(), risk_counts=get_risk_counts()), 404


if __name__ == "__main__":
    UPLOAD_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    init_db()
    app.run(debug=True, use_reloader=False)
