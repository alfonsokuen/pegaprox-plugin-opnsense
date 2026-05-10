"""Static checks for the Overview UI HTML.

We don't render the page in a real browser here — that requires a Flask
host and Playwright. These checks catch obvious regressions: the file
parses, the script is type=module, the table headers are present, the
banned design tells aren't sneaking back in.
"""
from __future__ import annotations

import pathlib
import re
from html.parser import HTMLParser


HTML_PATH = pathlib.Path(__file__).parent.parent / "opnsense.html"


class _MinimalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.errors: list[str] = []
        self.tags: list[str] = []
        self.has_module_script = False
        self.has_viewport_meta = False
        self.has_color_scheme_meta = False

    def error(self, message: str) -> None:  # pragma: no cover - parser API
        self.errors.append(message)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        attr_dict = {k: v for k, v in attrs}
        if tag == "script" and attr_dict.get("type") == "module":
            self.has_module_script = True
        if tag == "meta":
            if attr_dict.get("name") == "viewport":
                self.has_viewport_meta = True
            if attr_dict.get("name") == "color-scheme":
                self.has_color_scheme_meta = True


def _content() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def test_html_parses_without_errors():
    p = _MinimalParser()
    p.feed(_content())
    assert not p.errors


def test_html_has_required_meta_and_module_script():
    p = _MinimalParser()
    p.feed(_content())
    assert p.has_viewport_meta, "missing viewport meta"
    assert p.has_color_scheme_meta, "missing color-scheme meta"
    assert p.has_module_script, "main script must be type=module"


def test_html_uses_opnsense_overview_endpoint():
    body = _content()
    # Endpoint resolves under /api/plugins/opnsense/api/overview when served
    # by PegaProx; we only assert the relative path here.
    assert "../api/overview" in body


def test_html_has_industrial_brutalist_palette():
    body = _content()
    # Tactical Telemetry colours must be set as CSS variables, not pasted
    # ad-hoc on every selector.
    assert "--bg: #0a0a0a" in body
    assert "--fg: #eaeaea" in body
    assert "--red: #e61919" in body
    assert "--green: #4af626" in body
    # No border-radius rule is allowed (90deg corners enforce brutalism).
    assert not re.search(r"border-radius\s*:\s*[1-9]", body), (
        "border-radius is banned in this palette — keep corners square"
    )


def test_html_avoids_banned_ai_tells():
    body = _content().lower()
    # No gradient text trick.
    assert "background-clip: text" not in body
    assert "-webkit-background-clip: text" not in body
    # No purple-to-blue glow gradient.
    assert "linear-gradient(45deg, purple" not in body


def test_html_respects_reduced_motion():
    body = _content()
    assert "prefers-reduced-motion: reduce" in body
    # The shimmer animation must be cancelled under reduced motion.
    assert re.search(r"prefers-reduced-motion:\s*reduce[^}]*animation:\s*none", body, re.S)


def test_html_includes_aria_landmarks_and_busy_state():
    body = _content()
    assert 'role="banner"' in body
    assert 'aria-busy="true"' in body
    # Refresh button must be accessible.
    assert 'aria-label="Refresh overview"' in body


def test_html_has_responsive_breakpoints():
    body = _content()
    for px in (1280, 1024, 768):
        assert f"max-width: {px}px" in body, f"missing breakpoint at {px}px"
