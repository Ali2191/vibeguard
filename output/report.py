import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')


def generate_html_report(results: dict, output_path: str = None) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template('report.html')
    generated_at = datetime.now().strftime('%B %d, %Y at %H:%M')
    html = template.render(results=results, generated_at=generated_at)
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    return html


def generate_json_report(results: dict, output_path: str = None) -> str:
    content = json.dumps(results, indent=2)
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
    return content
