"""Report generation (JSON / simple HTML)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .helpers import safe_filename, timestamp


class ReportGenerator:
    def __init__(self, results: dict[str, Any], fmt: str = "json", output_dir: str = "reports"):
        self.results = results
        self.fmt = fmt.lower()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> str:
        target = self.results.get("target") or self.results.get("network") or self.results.get("domain") or "scan"
        name = f"{safe_filename(str(target))}_{timestamp()}.{self.fmt}"
        path = self.output_dir / name

        if self.fmt == "json":
            path.write_text(json.dumps(self.results, indent=2, default=str), encoding="utf-8")
        elif self.fmt == "html":
            path.write_text(self._html(), encoding="utf-8")
        else:
            # csv-ish fallback: one line summary
            path.write_text(json.dumps(self.results, default=str) + "\n", encoding="utf-8")

        return str(path)

    def _html(self) -> str:
        body = json.dumps(self.results, indent=2, default=str)
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SecureNet Report</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0a0f1a;color:#e2e8f0;padding:2rem}}
pre{{background:#0f1629;padding:1.25rem;border-radius:12px;overflow:auto;border:1px solid rgba(148,163,184,.15)}}
h1{{color:#22d3ee}}
</style></head>
<body>
<h1>SecureNet Toolkit Report</h1>
<pre>{body}</pre>
</body></html>"""
