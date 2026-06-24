from pytest_mock import MockerFixture

from cycode.cli.utils import host_info

_MODULE = 'cycode.cli.utils.host_info'

_IOREG_SAMPLE = """
    "IOPlatformUUID" = "00000000-0000-0000-0000-000000000000"
    "IOPlatformSerialNumber" = "AAAA888111"
"""
# platform_name mapping


def test_get_platform_name_maps_known_systems(mocker: MockerFixture) -> None:
    for system, expected in (('Darwin', 'macOS'), ('Windows', 'Windows'), ('Linux', 'Linux')):
        mocker.patch(f'{_MODULE}.platform.system', return_value=system)
        assert host_info.get_platform_name() == expected


def test_get_platform_name_falls_back_to_raw_system(mocker: MockerFixture) -> None:
    mocker.patch(f'{_MODULE}.platform.system', return_value='SunOS')
    assert host_info.get_platform_name() == 'SunOS'


# serial_number per platform


def test_get_serial_number_macos_parses_ioreg(mocker: MockerFixture) -> None:
    mocker.patch(f'{_MODULE}.platform.system', return_value='Darwin')
    mocker.patch(f'{_MODULE}._run', return_value=_IOREG_SAMPLE)
    assert host_info.get_serial_number() == 'AAAA888111'


def test_get_serial_number_windows_uses_command_output(mocker: MockerFixture) -> None:
    mocker.patch(f'{_MODULE}.platform.system', return_value='Windows')
    mocker.patch(f'{_MODULE}._run', return_value='ABC123XYZ')
    assert host_info.get_serial_number() == 'ABC123XYZ'


def test_get_serial_number_unsupported_platform_returns_none(mocker: MockerFixture) -> None:
    mocker.patch(f'{_MODULE}.platform.system', return_value='Linux')
    assert host_info.get_serial_number() is None


# Robustness: getters never raise, returning None when their backing call fails.


def test_get_serial_number_returns_none_when_command_raises(mocker: MockerFixture) -> None:
    mocker.patch(f'{_MODULE}.platform.system', return_value='Darwin')
    mocker.patch(f'{_MODULE}._run', side_effect=RuntimeError('subprocess failed'))
    assert host_info.get_serial_number() is None


def test_run_returns_none_on_failure(mocker: MockerFixture) -> None:
    mocker.patch(f'{_MODULE}.subprocess.run', side_effect=FileNotFoundError('missing'))
    assert host_info._run(['does-not-exist']) is None


def test_get_hostname_returns_none_on_error(mocker: MockerFixture) -> None:
    mocker.patch(f'{_MODULE}.socket.gethostname', side_effect=OSError('hostname unavailable'))
    assert host_info.get_hostname() is None


def test_get_last_login_user_returns_none_on_error(mocker: MockerFixture) -> None:
    mocker.patch(f'{_MODULE}.getpass.getuser', side_effect=KeyError('no user'))
    assert host_info.get_last_login_user() is None
