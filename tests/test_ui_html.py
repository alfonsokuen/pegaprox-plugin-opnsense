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


def test_html_uses_pegaprox_design_tokens():
    body = _content()
    # The plugin must blend with PegaProx's dashboard. Keep the same token
    # names + values lifted from docker_swarm/swarm.html so a future PegaProx
    # palette refresh affects us in lockstep.
    for token in (
        "--accent: #e57000",
        "--bg: #0f1117",
        "--card: #1a1d27",
        "--border: #2a2d3a",
        "--text: #e4e4e7",
        # --muted is bumped to zinc-400 (#a1a1aa) over PegaProx's #71717a so
        # body text on --card clears WCAG AA contrast (4.5:1).
        "--muted: #a1a1aa",
        "--green: #22c55e",
        "--red: #ef4444",
        "--yellow: #eab308",
        "--blue: #3b82f6",
    ):
        assert token in body, f"missing PegaProx token: {token}"


def test_html_supports_theme_query_param():
    body = _content()
    # PegaProx passes ?theme=corp-light|corp-dark when embedding the iframe.
    # The plugin must honour at least the light variant.
    assert "theme-light" in body
    assert 'params.get("theme")' in body or "params.get('theme')" in body


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
    # Refresh button must be accessible (label may be ES or EN).
    assert ('aria-label="Refresh overview"' in body
            or 'aria-label="Refrescar overview"' in body
            or 'aria-label="Refrescar vista"' in body)


def test_html_has_tablist_with_four_tabs():
    body = _content()
    assert 'role="tablist"' in body, "missing tablist landmark"
    for tab in ("overview", "network", "vpn", "logs"):
        assert f'data-tab="{tab}"' in body, f"missing tab: {tab}"
    # Exactly one tab must declare aria-selected="true" in markup
    # (excluding the CSS selector that also contains the same string).
    in_markup = re.findall(r'<button[^>]*aria-selected="true"[^>]*>', body)
    assert len(in_markup) == 1


def test_html_uses_per_tab_endpoints():
    body = _content()
    for ep in ("../api/overview", "../api/network", "../api/logs"):
        assert ep in body, f"missing endpoint reference: {ep}"


def test_html_has_responsive_breakpoints():
    body = _content()
    for px in (1280, 1024, 768):
        assert f"max-width: {px}px" in body, f"missing breakpoint at {px}px"
