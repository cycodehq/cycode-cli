import sys
import types
from pathlib import Path
from typing import Optional

import pytest

from cycode.cli.utils import host_info

_MACHINE_GUID = 'e0e8e0a1-2222-4c3f-9d4a-000000000001'
_IOREG_OUTPUT = """
  +-o Root  <class IORegistryEntry, id 1, retain 42>
      "IOPlatformSerialNumber" = "C02XY1234567"
"""


@pytest.fixture(autouse=True)
def _home_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, 'home', classmethod(lambda _cls: tmp_path))
    return tmp_path


def _fake_winreg(machine_guid: Optional[str] = _MACHINE_GUID) -> types.ModuleType:
    module = types.ModuleType('winreg')
    module.HKEY_LOCAL_MACHINE = 0
    module.KEY_READ = 0x20019
    module.KEY_WOW64_64KEY = 0x0100

    class _Key:
        def __enter__(self) -> '_Key':  # noqa: PYI034
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def open_key(_hive: int, sub_key: str, _reserved: int, access: int) -> _Key:
        assert sub_key == r'SOFTWARE\Microsoft\Cryptography'
        assert access & module.KEY_WOW64_64KEY  # must read the 64-bit view, not WOW6432Node
        return _Key()

    def query_value_ex(_key: '_Key', name: str) -> tuple:
        assert name == 'MachineGuid'
        if machine_guid is None:
            raise FileNotFoundError(name)
        return machine_guid, 1

    module.OpenKey = open_key
    module.QueryValueEx = query_value_ex
    return module


@pytest.fixture
def _windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_info.platform, 'system', lambda: 'Windows')


def test_cache_path_is_under_cycode_home_and_not_temp(tmp_path: Path) -> None:
    cache_path = host_info._serial_number_cache_path()
    assert cache_path == tmp_path / '.cycode' / 'device-id'


def test_cached_value_short_circuits_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cache_path = tmp_path / '.cycode' / 'device-id'
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text('CACHED-ID', encoding='utf-8')

    def _fail() -> str:
        raise AssertionError('must not resolve when the cache is warm')

    monkeypatch.setattr(host_info, '_resolve_serial_number', _fail)

    assert host_info.get_serial_number() == 'CACHED-ID'


@pytest.mark.usefixtures('_windows')
def test_windows_reads_machine_guid_and_caches_it(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setitem(sys.modules, 'winreg', _fake_winreg())

    assert host_info.get_serial_number() == _MACHINE_GUID
    assert (tmp_path / '.cycode' / 'device-id').read_text(encoding='utf-8') == _MACHINE_GUID


@pytest.mark.usefixtures('_windows')
def test_windows_falls_back_to_generated_uuid_and_reuses_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, 'winreg', _fake_winreg(machine_guid=None))

    first = host_info.get_serial_number()
    second = host_info.get_serial_number()

    assert first is not None
    assert first == second  # persisted, so the id is stable across processes


@pytest.mark.usefixtures('_windows')
def test_windows_write_removes_legacy_temp_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    legacy_dir = tmp_path / 'temp'
    legacy_dir.mkdir()
    monkeypatch.setattr(host_info.tempfile, 'gettempdir', lambda: str(legacy_dir))
    monkeypatch.setattr(host_info.getpass, 'getuser', lambda: 'tester')
    legacy_path = legacy_dir / '.cycode-device-serial-tester'
    legacy_path.write_text('OLD-BIOS-SERIAL', encoding='utf-8')

    monkeypatch.setitem(sys.modules, 'winreg', _fake_winreg())

    assert host_info.get_serial_number() == _MACHINE_GUID
    assert not legacy_path.exists()


def test_macos_serial_number_is_parsed_from_ioreg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_info.platform, 'system', lambda: 'Darwin')
    monkeypatch.setattr(host_info, '_run', lambda *_args, **_kwargs: _IOREG_OUTPUT)

    assert host_info.get_serial_number() == 'C02XY1234567'


def test_linux_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_info.platform, 'system', lambda: 'Linux')

    assert host_info.get_serial_number() is None
