"""Get the unique machine id of any host (without admin privileges)

Based on methods from: https://github.com/denisbrodbeck/machineid
The MIT License (MIT)
"""

import hashlib
import hmac
from sys import platform
from typing import Optional
from functools import lru_cache

from cycode.cli.exceptions.custom_exceptions import CycodeError
from cycode.cli.utils.shell_executor import shell


def _read_cmd(cmd: str) -> Optional[str]:
    try:
        return shell(cmd, execute_in_shell=True)
    except:  # noqa
        return None


def _read_registry(registry: str, key: str) -> Optional[str]:
    import winreg

    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
        with winreg.OpenKey(reg, registry) as key_object:
            try:
                value, _ = winreg.QueryValueEx(key_object, key)
                return value
            except WindowsError:
                pass

    return None


def _read_file(path: str) -> Optional[str]:
    try:
        with open(path, encoding='UTF-8') as f:
            return f.read()
    except:  # noqa
        return None


def _get_darwin_machine_id() -> str:
    return _read_cmd("ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'")


def _get_windows_machine_id() -> str:
    mid = _read_registry('SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY', 'MachineGuid')
    if not mid:
        mid = _read_cmd('wmic csproduct get uuid').split('\n')[2].strip()

    return mid


def _get_linux_machine_id() -> str:
    mid = _read_file('/var/lib/dbus/machine-id')

    if not mid:
        mid = _read_file('/etc/machine-id')

    if not mid:
        cgroup = _read_file('/proc/self/cgroup')
        if cgroup and 'docker' in cgroup:
            mid = _read_cmd('head -1 /proc/self/cgroup | cut -d/ -f3')

    if not mid:
        mountinfo = _read_file('/proc/self/mountinfo')
        if mountinfo and 'docker' in mountinfo:
            mid = _read_cmd("grep 'systemd' /proc/self/mountinfo | cut -d/ -f3")

    return mid


def _get_bsd_machine_id() -> str:
    mid = _read_file('/etc/hostid')
    if not mid:
        mid = _read_cmd('kenv -q smbios.system.uuid')

    return mid


def _get_machine_id() -> str:
    if platform == 'darwin':
        mid = _get_darwin_machine_id()
    elif platform in {'win32', 'cygwin', 'msys'}:
        mid = _get_windows_machine_id()
    elif platform.startswith('linux'):
        mid = _get_linux_machine_id()
    elif platform.startswith('openbsd') or platform.startswith('freebsd'):
        mid = _get_bsd_machine_id()
    else:
        raise CycodeError('Unknown platform')

    if mid is None:
        raise CycodeError("Can't get Machine ID")

    return mid


def _get_hmac_hex(key: str, msg: str) -> str:
    return hmac.new(key=key.encode(), msg=msg.encode(), digestmod=hashlib.sha256).hexdigest()


@lru_cache(maxsize=None)
def machine_id() -> str:
    return _get_machine_id()


@lru_cache(maxsize=None)
def protected_machine_id(app_id: str) -> str:
    """Calculates HMAC-SHA256 of the app ID, keyed by the machine ID and returns a hex-encoded str."""
    return _get_hmac_hex(key=_get_machine_id(), msg=app_id)
