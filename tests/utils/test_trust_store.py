import platform
import sys
from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest

from cycode.cli import consts
from cycode.cli.utils import trust_store


@pytest.fixture(autouse=True)
def _reset_trust_store() -> Iterator[None]:
    """Keep the module-level install flag from leaking between tests."""
    trust_store._installed = False
    yield
    trust_store._installed = False


@pytest.fixture
def mocked_truststore(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Stub out the real truststore module, so we never patch `ssl` in the test process."""
    module = MagicMock()
    monkeypatch.setitem(sys.modules, 'truststore', module)
    return module


def _disable_via_env(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    # cycode.config snapshots os.environ at import time, so monkeypatch.setenv alone isn't visible
    monkeypatch.setitem(trust_store.config.configuration, consts.DISABLE_TRUSTSTORE_ENV_VAR_NAME, value)


def test_install_injects_os_trust_store(mocked_truststore: MagicMock) -> None:
    assert trust_store.install() is True
    assert trust_store.is_installed() is True
    mocked_truststore.inject_into_ssl.assert_called_once_with()


def test_install_is_idempotent(mocked_truststore: MagicMock) -> None:
    assert trust_store.install() is True
    assert trust_store.install() is True
    mocked_truststore.inject_into_ssl.assert_called_once_with()


@pytest.mark.parametrize('value', ['1', 'true', 'TRUE', 'yes', 'on', 'enabled'])
def test_install_skipped_when_disabled_by_env_var(
    value: str, mocked_truststore: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    _disable_via_env(monkeypatch, value)

    assert trust_store.install() is False
    assert trust_store.is_installed() is False
    mocked_truststore.inject_into_ssl.assert_not_called()


@pytest.mark.parametrize('value', ['0', 'false', 'no', ''])
def test_install_not_skipped_for_falsy_env_var(
    value: str, mocked_truststore: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    _disable_via_env(monkeypatch, value)

    assert trust_store.install() is True
    mocked_truststore.inject_into_ssl.assert_called_once_with()


def test_install_skipped_on_unsupported_python(mocked_truststore: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trust_store.sys, 'version_info', (3, 9, 21))

    assert trust_store.install() is False
    assert trust_store.is_installed() is False
    mocked_truststore.inject_into_ssl.assert_not_called()


def test_install_swallows_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    original_import = builtins.__import__

    def _raising_import(name: str, *args, **kwargs):  # noqa: ANN202
        if name == 'truststore':
            raise ImportError('truststore is not installed')
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', _raising_import)

    assert trust_store.install() is False
    assert trust_store.is_installed() is False


def test_install_swallows_injection_error(mocked_truststore: MagicMock) -> None:
    mocked_truststore.inject_into_ssl.side_effect = RuntimeError('no trust store on this machine')

    assert trust_store.install() is False
    assert trust_store.is_installed() is False


# --- session integration ---


def _get_fresh_session():  # noqa: ANN202
    from cycode.cyclient.cycode_client_base import _get_session

    _get_session.cache_clear()
    try:
        return _get_session()
    finally:
        _get_session.cache_clear()


@pytest.mark.skipif(platform.system() != 'Windows', reason='the legacy fallback is Windows-only')
def test_session_skips_legacy_windows_adapter_when_trust_store_installed(
    mocked_truststore: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cycode.cyclient.cycode_client_base import SystemStorageSslContext

    monkeypatch.delenv('REQUESTS_CA_BUNDLE', raising=False)
    monkeypatch.delenv('CURL_CA_BUNDLE', raising=False)
    trust_store.install()

    session = _get_fresh_session()

    assert not isinstance(session.get_adapter('https://cycode.com'), SystemStorageSslContext)


@pytest.mark.skipif(platform.system() != 'Windows', reason='the legacy fallback is Windows-only')
def test_session_uses_legacy_windows_adapter_without_trust_store(monkeypatch: pytest.MonkeyPatch) -> None:
    from cycode.cyclient.cycode_client_base import SystemStorageSslContext

    monkeypatch.delenv('REQUESTS_CA_BUNDLE', raising=False)
    monkeypatch.delenv('CURL_CA_BUNDLE', raising=False)

    session = _get_fresh_session()

    assert isinstance(session.get_adapter('https://cycode.com'), SystemStorageSslContext)
