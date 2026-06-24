import getpass
import platform
import re
import socket
import subprocess
from typing import Optional

from cycode.logger import get_logger

logger = get_logger('HOST INFO')

_SUBPROCESS_TIMEOUT_SEC = 5

_PLATFORM_NAMES = {'Darwin': 'macOS', 'Windows': 'Windows', 'Linux': 'Linux'}
_LINUX_SERIAL_PATH = '/sys/class/dmi/id/product_serial'


def _run(command: list, timeout: int = _SUBPROCESS_TIMEOUT_SEC) -> Optional[str]:
    """Run a command and return its stripped stdout. Never raises; returns None on any error."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)  # noqa: S603
        return result.stdout.strip() or None
    except Exception as e:
        logger.debug('Failed to run command %s', command, exc_info=e)
        return None


def _read_text_file(path: str) -> Optional[str]:
    """Read and strip a text file. Never raises; returns None if it can't be read."""
    try:
        with open(path) as text_file:
            return text_file.read().strip() or None
    except OSError:
        return None


def get_hostname() -> Optional[str]:
    try:
        return socket.gethostname() or None
    except Exception as e:
        logger.debug('Failed to resolve hostname', exc_info=e)
        return None


def get_platform_name() -> Optional[str]:
    try:
        system = platform.system()
        return _PLATFORM_NAMES.get(system, system or None)
    except Exception as e:
        logger.debug('Failed to resolve platform name', exc_info=e)
        return None


def get_os_version() -> Optional[str]:
    try:
        system = platform.system()
        if system == 'Darwin':
            return platform.mac_ver()[0] or None
        if system == 'Windows':
            return platform.win32_ver()[1] or platform.version() or None
        if system == 'Linux':
            return _get_linux_os_version()
        return platform.release() or None
    except Exception as e:
        logger.debug('Failed to resolve OS version', exc_info=e)
        return None


def _get_linux_os_version() -> Optional[str]:
    freedesktop_os_release = getattr(platform, 'freedesktop_os_release', None)  # Python 3.10+
    if freedesktop_os_release is not None:
        try:
            version_id = freedesktop_os_release().get('VERSION_ID')
            if version_id:
                return version_id
        except OSError:
            pass

    os_release = _read_text_file('/etc/os-release')  # Python 3.9 fallback: parse manually
    if os_release:
        for line in os_release.splitlines():
            if line.startswith('VERSION_ID='):
                return line.split('=', 1)[1].strip().strip('"') or None

    return platform.release() or None


def get_last_login_user() -> Optional[str]:
    try:
        return getpass.getuser() or None
    except Exception as e:
        logger.debug('Failed to resolve last login user', exc_info=e)
        return None


def get_serial_number() -> Optional[str]:
    try:
        system = platform.system()
        if system == 'Darwin':
            return _get_macos_serial_number()
        if system == 'Windows':
            return _run(
                ['powershell', '-NoProfile', '-Command', '(Get-CimInstance -ClassName Win32_BIOS).SerialNumber']
            )
        if system == 'Linux':
            return _read_text_file(_LINUX_SERIAL_PATH)
    except Exception as e:
        logger.debug('Failed to resolve serial number', exc_info=e)
    return None


def _get_macos_serial_number() -> Optional[str]:
    output = _run(['ioreg', '-c', 'IOPlatformExpertDevice', '-d', '2'])
    if not output:
        return None
    match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', output)
    return match.group(1) if match else None
