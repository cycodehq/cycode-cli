import inspect
import sys
from collections.abc import Iterator
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from cycode.cli import consts
from cycode.cli.utils import trust_store

if TYPE_CHECKING:
    import requests


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


def _set_enable_env(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    # cycode.config snapshots os.environ at import time, so monkeypatch.setenv alone isn't visible
    monkeypatch.setitem(trust_store.config.configuration, consts.ENABLE_TRUSTSTORE_ENV_VAR_NAME, value)


@pytest.fixture
def opted_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """The OS trust store is opt-in, so most tests must turn it on explicitly."""
    _set_enable_env(monkeypatch, '1')


# On Python 3.9 truststore is neither installed nor importable, and install() refuses by design,
# so the tests that assert a successful injection cannot run there.
requires_truststore = pytest.mark.skipif(
    sys.version_info < trust_store._MIN_PYTHON_VERSION,
    reason='truststore requires Python 3.10+',
)


@pytest.mark.skipif(
    sys.version_info >= trust_store._MIN_PYTHON_VERSION,
    reason='covers the Python 3.9 fallback only',
)
def test_install_declines_on_python_39(mocked_truststore: MagicMock, opted_in: None) -> None:
    assert trust_store.install() is False
    assert trust_store.is_installed() is False
    mocked_truststore.inject_into_ssl.assert_not_called()


@requires_truststore
def test_install_injects_os_trust_store(mocked_truststore: MagicMock, opted_in: None) -> None:
    assert trust_store.install() is True
    assert trust_store.is_installed() is True
    mocked_truststore.inject_into_ssl.assert_called_once_with()


@requires_truststore
def test_install_is_idempotent(mocked_truststore: MagicMock, opted_in: None) -> None:
    assert trust_store.install() is True
    assert trust_store.install() is True
    mocked_truststore.inject_into_ssl.assert_called_once_with()


@pytest.mark.parametrize('value', ['1', 'true', 'TRUE', 'yes', 'on', 'enabled'])
def test_install_runs_when_opted_in(value: str, mocked_truststore: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_enable_env(monkeypatch, value)

    assert trust_store.is_enabled() is True
    if trust_store.is_supported():
        assert trust_store.install() is True
        mocked_truststore.inject_into_ssl.assert_called_once_with()


@pytest.mark.parametrize('value', ['0', 'false', 'no', ''])
def test_install_skipped_when_not_opted_in(
    value: str, mocked_truststore: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_enable_env(monkeypatch, value)

    assert trust_store.is_enabled() is False
    assert trust_store.install() is False
    assert trust_store.is_installed() is False
    mocked_truststore.inject_into_ssl.assert_not_called()


def test_install_skipped_when_env_var_absent(mocked_truststore: MagicMock) -> None:
    """The default with no configuration at all: certifi, exactly as before this feature."""
    assert trust_store.is_enabled() is False
    assert trust_store.install() is False
    mocked_truststore.inject_into_ssl.assert_not_called()


def test_install_skipped_on_unsupported_python(
    mocked_truststore: MagicMock, monkeypatch: pytest.MonkeyPatch, opted_in: None
) -> None:
    monkeypatch.setattr(trust_store.sys, 'version_info', (3, 9, 21))

    assert trust_store.install() is False
    assert trust_store.is_installed() is False
    mocked_truststore.inject_into_ssl.assert_not_called()


@requires_truststore
def test_install_swallows_import_error(monkeypatch: pytest.MonkeyPatch, opted_in: None) -> None:
    import builtins

    original_import = builtins.__import__

    def _raising_import(name: str, *args, **kwargs):  # noqa: ANN202
        if name == 'truststore':
            raise ImportError('truststore is not installed')
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', _raising_import)

    assert trust_store.install() is False
    assert trust_store.is_installed() is False


@requires_truststore
def test_install_swallows_injection_error(mocked_truststore: MagicMock, opted_in: None) -> None:
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


def test_session_installs_the_trust_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guards the wiring: without this, deleting the install() call leaves every other test green."""
    called = []
    monkeypatch.setattr(trust_store, 'install', lambda: called.append(True))

    _get_fresh_session()

    assert called, '_get_session() must install the OS trust store before the first handshake'


def test_presigned_upload_installs_the_trust_store() -> None:
    """The S3 presigned upload bypasses the shared session, so it installs the trust store itself."""
    import cycode.cyclient.scan_client as scan_client_module

    source = inspect.getsource(scan_client_module.ScanClient.upload_to_presigned_post)
    assert 'trust_store.install()' in source
    assert source.index('trust_store.install()') < source.index('requests.post('), (
        'the trust store must be installed before the request is issued'
    )


def _windows_session(monkeypatch: pytest.MonkeyPatch, *, installed: bool) -> 'requests.Session':
    """Build a session as if we were on Windows, with the trust-store state fully pinned.

    platform.system() is faked so these run on every OS, and install() is stubbed so no test
    ever patches `ssl` for real.
    """
    import cycode.cyclient.cycode_client_base as base

    monkeypatch.setattr(base.platform, 'system', lambda: 'Windows')
    monkeypatch.setattr(base.trust_store, 'install', lambda: None)
    monkeypatch.setattr(base.trust_store, 'is_installed', lambda: installed)
    monkeypatch.delenv('REQUESTS_CA_BUNDLE', raising=False)
    monkeypatch.delenv('CURL_CA_BUNDLE', raising=False)
    return _get_fresh_session()


def _mounts_legacy_adapter(session: 'requests.Session') -> bool:
    from cycode.cyclient.cycode_client_base import SystemStorageSslContext

    return isinstance(session.get_adapter('https://cycode.com'), SystemStorageSslContext)


def test_windows_legacy_adapter_skipped_when_trust_store_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """truststore already covers Windows, so the legacy adapter must not be mounted on top."""
    session = _windows_session(monkeypatch, installed=True)

    assert _mounts_legacy_adapter(session) is False


def test_windows_legacy_adapter_kept_when_trust_store_inactive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whether the user simply did not opt in, or is on Python 3.9 where it is unavailable, Windows
    must keep behaving exactly as it did before this feature.
    """
    session = _windows_session(monkeypatch, installed=False)

    assert _mounts_legacy_adapter(session) is True
