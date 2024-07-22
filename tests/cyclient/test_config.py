from typing import TYPE_CHECKING

from cycode.cli.consts import DEFAULT_CYCODE_DOMAIN
from cycode.cyclient.config import _is_on_premise_installation

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


def test_is_on_premise_installation(monkeypatch: 'MonkeyPatch') -> None:
    monkeypatch.setattr('cycode.cyclient.config.cycode_api_url', 'api.cycode.com')
    assert not _is_on_premise_installation(DEFAULT_CYCODE_DOMAIN)
    monkeypatch.setattr('cycode.cyclient.config.cycode_api_url', 'api.eu.cycode.com')
    assert not _is_on_premise_installation(DEFAULT_CYCODE_DOMAIN)

    monkeypatch.setattr('cycode.cyclient.config.cycode_api_url', 'cycode.google.com')
    assert _is_on_premise_installation(DEFAULT_CYCODE_DOMAIN)
    monkeypatch.setattr('cycode.cyclient.config.cycode_api_url', 'cycode.blabla.google.com')
    assert _is_on_premise_installation(DEFAULT_CYCODE_DOMAIN)

    monkeypatch.setattr('cycode.cyclient.config.cycode_api_url', 'api.cycode.com')
    assert _is_on_premise_installation('blabla')
    monkeypatch.setattr('cycode.cyclient.config.cycode_api_url', 'cycode.blabla.google.com')
    assert _is_on_premise_installation('blabla')
