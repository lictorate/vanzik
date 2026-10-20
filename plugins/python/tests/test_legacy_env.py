"""The AGENTGUARD_* variables the SDK read before Vanzik 2.0.

They are never read. A Guard that would have fallen back to one raises
instead of running without it (no API key, another server, the default
tenant's policy). An explicit argument, or the VANZIK_* variable, makes the
old one irrelevant.
"""

import pytest

from vanzik import Guard

NAMES = ("URL", "API_KEY", "TENANT_ID")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in NAMES:
        monkeypatch.delenv("VANZIK_" + name, raising=False)
        monkeypatch.delenv("AGENTGUARD_" + name, raising=False)


@pytest.mark.parametrize("name", NAMES)
def test_old_variable_alone_raises(monkeypatch, name):
    monkeypatch.setenv("AGENTGUARD_" + name, "old")
    with pytest.raises(ValueError, match="VANZIK_" + name):
        Guard()


def test_explicit_arguments_make_the_old_variables_irrelevant(monkeypatch):
    for name in NAMES:
        monkeypatch.setenv("AGENTGUARD_" + name, "old")
    g = Guard(base_url="http://new:8080", api_key="k", tenant_id="acme")
    assert (g.base_url, g.api_key, g.tenant_id) == ("http://new:8080", "k", "acme")


def test_new_variable_wins(monkeypatch):
    for name in NAMES:
        monkeypatch.setenv("AGENTGUARD_" + name, "old")
        monkeypatch.setenv("VANZIK_" + name, "new")
    g = Guard()
    assert (g.base_url, g.api_key, g.tenant_id) == ("new", "new", "new")
