import os
import re
from pathlib import Path
from flask import Blueprint, render_template, abort, current_app

docs_bp = Blueprint("docs", __name__, url_prefix="/docs")

DOC_TITLES = {
    "project_report": "Comprehensive Project Report",
    "architecture": "System Architecture & Threat Model",
    "installation_guide": "Installation & Environment Setup Guide",
    "practical_manual": "Laboratory Practical Manual (CNS Experiments 1-9)",
    "testing_report": "Automated Testing & Verification Report",
    "security_considerations": "Security Considerations & Safe Execution Policy",
    "viva_questions": "Viva Voce & Oral Examination Preparation Guide",
}


def basic_markdown_to_html(md_text: str) -> str:
    """Converts markdown text to clean HTML without requiring heavy external parsers."""
    # Escape raw HTML tags
    html = md_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Headers
    html = re.sub(r"^### (.*?)$", r"<h3>\1</h3>", html, flags=re.MULTILINE)
    html = re.sub(r"^## (.*?)$", r"<h2>\1</h2>", html, flags=re.MULTILINE)
    html = re.sub(r"^# (.*?)$", r"<h1>\1</h1>", html, flags=re.MULTILINE)

    # Bold and italics
    html = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", html)
    html = re.sub(r"\*(.*?)\*", r"<em>\1</em>", html)

    # Code blocks
    html = re.sub(r"```([a-zA-Z0-9_\-]*)\n(.*?)```", r"<pre class='p-3 bg-dark text-info rounded border border-secondary'><code>\2</code></pre>", html, flags=re.DOTALL)
    # Inline code
    html = re.sub(r"`([^`]+)`", r"<code class='text-cyan bg-navy-light px-1 py-0.5 rounded'>\1</code>", html)

    # Bullet lists
    html = re.sub(r"^\- (.*?)$", r"<li>\1</li>", html, flags=re.MULTILINE)
    html = re.sub(r"(<li>.*?</li>)", r"<ul class='list-unstyled ms-3'>\1</ul>", html, flags=re.DOTALL)

    # Paragraphs
    paragraphs = html.split("\n\n")
    processed = []
    for p in paragraphs:
        p = p.strip()
        if not p.startswith("<h") and not p.startswith("<pre") and not p.startswith("<ul") and not p.startswith("<blockquote"):
            processed.append(f"<p>{p.replace(chr(10), '<br>')}</p>")
        else:
            processed.append(p)

    return "\n".join(processed)


@docs_bp.route("/")
def list_docs():
    docs_dir = Path(current_app.config["BASE_DIR"]) / "docs"
    docs_list = []
    for slug, title in DOC_TITLES.items():
        doc_path = docs_dir / f"{slug}.md"
        exists = doc_path.exists()
        size_kb = round(doc_path.stat().st_size / 1024, 1) if exists else 0
        docs_list.append({
            "slug": slug,
            "title": title,
            "filename": f"{slug}.md",
            "exists": exists,
            "size_kb": size_kb,
        })
    return render_template("docs/docs_index.html", docs=docs_list)


@docs_bp.route("/<slug>")
def view_doc(slug):
    if slug not in DOC_TITLES:
        abort(404)

    docs_dir = Path(current_app.config["BASE_DIR"]) / "docs"
    doc_path = docs_dir / f"{slug}.md"
    if not doc_path.exists():
        abort(404)

    with open(doc_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    rendered_html = basic_markdown_to_html(md_content)

    return render_template(
        "docs/doc_view.html",
        slug=slug,
        title=DOC_TITLES[slug],
        raw_markdown=md_content,
        rendered_html=rendered_html,
        all_docs=DOC_TITLES,
    )
