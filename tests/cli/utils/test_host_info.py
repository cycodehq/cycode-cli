from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest

from cycode.cli.utils import host_info

_SERIAL = 'C02XY1234567'
_IOREG_OUTPUT = """
  +-o Root  <class IORegistryEntry, id 1, retain 42>
      "IOPlatformSerialNumber" = "C02XY1234567"
"""


@pytest.fixture(autouse=True)
def _temp_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(host_info.tempfile, 'gettempdir', lambda: str(tmp_path))
    monkeypatch.setattr(host_info.getpass, 'getuser', lambda: 'tester')
    return tmp_path


def _cache_path(tmp_path: Path) -> Path:
    return tmp_path / '.cycode-device-serial-tester'


class _ComCalls:
    def __init__(self) -> None:
        self.initialized = 0
        self.uninitialized = 0


def _install_fake_pywin32(
    monkeypatch: pytest.MonkeyPatch,
    serial: Optional[str] = _SERIAL,
    get_object_error: Optional[Exception] = None,
) -> _ComCalls:
    calls = _ComCalls()

    pythoncom = SimpleNamespace(
        CoInitialize=lambda: setattr(calls, 'initialized', calls.initialized + 1),
        CoUninitialize=lambda: setattr(calls, 'uninitialized', calls.uninitialized + 1),
    )

    class _Bios:
        SerialNumber = serial

    class _WmiService:
        def InstancesOf(self, class_name: str) -> list:  # noqa: N802 - mirrors the COM API
            assert class_name == 'Win32_BIOS'
            return [_Bios()]

    def get_object(moniker: str) -> _WmiService:
        assert moniker == 'winmgmts:'
        if get_object_error is not None:
            raise get_object_error
        return _WmiService()

    win32com_client = SimpleNamespace(GetObject=get_object)

    # host_info imports pywin32 at module level (guarded by sys.platform), so patch the bound names
    monkeypatch.setattr(host_info, 'pythoncom', pythoncom, raising=False)
    monkeypatch.setattr(host_info, 'win32com_client', win32com_client, raising=False)
    return calls


@pytest.fixture
def _windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_info.platform, 'system', lambda: 'Windows')


def test_cache_path_is_per_user_in_the_temp_dir(tmp_path: Path) -> None:
    assert host_info._serial_number_cache_path() == _cache_path(tmp_path)


def test_cached_value_short_circuits_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _cache_path(tmp_path).write_text('CACHED-ID', encoding='utf-8')

    def _fail() -> str:
        raise AssertionError('must not resolve when the cache is warm')

    monkeypatch.setattr(host_info, '_resolve_serial_number', _fail)

    assert host_info.get_serial_number() == 'CACHED-ID'


@pytest.mark.usefixtures('_windows')
def test_windows_reads_bios_serial_over_wmi_and_caches_it(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _install_fake_pywin32(monkeypatch)

    assert host_info.get_serial_number() == _SERIAL
    assert _cache_path(tmp_path).read_text(encoding='utf-8') == _SERIAL
    assert (calls.initialized, calls.uninitialized) == (1, 1)


@pytest.mark.usefixtures('_windows')
def test_windows_uninitializes_com_when_wmi_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _install_fake_pywin32(monkeypatch, get_object_error=OSError('WMI is unavailable'))

    assert host_info.get_serial_number() is None
    assert (calls.initialized, calls.uninitialized) == (1, 1)
    assert not _cache_path(tmp_path).exists()


@pytest.mark.usefixtures('_windows')
def test_windows_blank_serial_is_none_and_not_cached(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_fake_pywin32(monkeypatch, serial='   ')

    assert host_info.get_serial_number() is None
    assert not _cache_path(tmp_path).exists()


@pytest.mark.usefixtures('_windows')
def test_windows_without_pywin32_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_info, 'pythoncom', None, raising=False)
    monkeypatch.setattr(host_info, 'win32com_client', None, raising=False)

    assert host_info.get_serial_number() is None


def test_macos_serial_number_is_parsed_from_ioreg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_info.platform, 'system', lambda: 'Darwin')
    monkeypatch.setattr(host_info, '_run', lambda *_args, **_kwargs: _IOREG_OUTPUT)

    assert host_info.get_serial_number() == _SERIAL


def test_linux_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_info.platform, 'system', lambda: 'Linux')

    assert host_info.get_serial_number() is None
