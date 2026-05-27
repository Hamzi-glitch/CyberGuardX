from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def generate_report(incident, output_dir, template_dir, css_url="../static/style.css"):
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    environment = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = environment.get_template("report.html")
    report_filename = f"incident_{incident['id']}.html"
    report_path = output_dir / report_filename

    rendered = template.render(
        incident=incident,
        css_url=css_url,
        generated=False,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    report_path.write_text(rendered, encoding="utf-8")
    return report_filename
