from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, PackageLoader, TemplateNotFound, select_autoescape
from jinja2.filters import do_tojson

from .models import AnalysisResult


class ReportBuilder:
    def __init__(self, template_dir: Optional[Path] = None):
        loaders = []
        if template_dir:
            loaders.append(FileSystemLoader(str(template_dir)))
        loaders.append(PackageLoader("spamreporter", "templates"))
        self.env = Environment(
            loader=ChoiceLoader(loaders),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters.setdefault("tojson", do_tojson)

    def render_html(self, result: AnalysisResult, lang: Optional[str] = None) -> str:
        template = self._resolve_template(kind="html", lang=lang or result.preferred_language)
        return template.render(
            result=result,
            analysis=result.to_dict(),
            contacts=result.abuse_contacts,
            metadata=result.metadata,
            rdap=result.rdap_record,
            domain=result.domain_record,
        )

    def render_text(self, result: AnalysisResult, lang: Optional[str] = None) -> str:
        template = self._resolve_template(kind="txt", lang=lang or result.preferred_language)
        return template.render(
            result=result,
            analysis=result.to_dict(),
            contacts=result.abuse_contacts,
            metadata=result.metadata,
        )

    def _resolve_template(self, kind: str, lang: str):
        names = [
            f"report_{lang}.{kind}.j2",
            f"report_en.{kind}.j2",
        ]
        for name in names:
            try:
                return self.env.get_template(name)
            except TemplateNotFound:
                continue
        raise TemplateNotFound(f"report_en.{kind}.j2")

    @staticmethod
    def json_dump(result: AnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2, default=str)
