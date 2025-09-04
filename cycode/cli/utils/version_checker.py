import os
import re
import time
from pathlib import Path
from typing import Optional

from cycode.cli.console import console
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.path_utils import get_file_content
from cycode.cyclient.cycode_client_base import CycodeClientBase
from cycode.logger import get_logger

logger = get_logger('Version Checker')


def _compare_versions(
    current_parts: list[int],
    latest_parts: list[int],
    current_is_pre: bool,
    latest_is_pre: bool,
    latest_version: str,
) -> Optional[str]:
    """Compare version numbers and determine if an update is needed.

    Implements version comparison logic with special handling for pre-release versions:
    - Won't suggest downgrading from stable to pre-release
    - Will suggest upgrading from pre-release to stable of the same version

    Args:
        current_parts: List of numeric version components for the current version
        latest_parts: List of numeric version components for the latest version
        current_is_pre: Whether the current version is pre-release
        latest_is_pre: Whether the latest version is pre-release
        latest_version: The full latest version string

    Returns:
        str | None: The latest version string if an update is recommended,
                   None if no update is needed

    """
    # If current is stable and latest is pre-release, don't suggest update
    if not current_is_pre and latest_is_pre:
        return None

    # Compare version numbers
    for current, latest in zip(current_parts, latest_parts):
        if latest > current:
            return latest_version
        if current > latest:
            return None

    # If all numbers are equal, suggest update if current is pre-release and latest is stable
    if current_is_pre and not latest_is_pre:
        return latest_version

    return None


class VersionChecker(CycodeClientBase):
    PYPI_API_URL = 'https://pypi.org/pypi'
    PYPI_PACKAGE_NAME = 'cycode'
    PYPI_REQUEST_TIMEOUT = 1

    GIT_CHANGELOG_URL_PREFIX = 'https://github.com/cycodehq/cycode-cli/releases/tag/v'

    DAILY = 24 * 60 * 60  # 24 hours in seconds
    WEEKLY = DAILY * 7

    def __init__(self) -> None:
        """Initialize the VersionChecker.

        Sets up the version checker with PyPI API URL and configure the cache file location
        using the global configuration directory.
        """
        super().__init__(self.PYPI_API_URL)

        configuration_manager = ConfigurationManager()
        config_dir = configuration_manager.global_config_file_manager.get_config_directory_path()
        self.cache_file = Path(config_dir) / '.version_check'

    def get_latest_version(self) -> Optional[str]:
        """Fetch the latest version of the package from PyPI.

        Makes an HTTP request to PyPI's JSON API to get the latest version information.

        Returns:
            str | None: The latest version string if successful, None if the request fails
                       or the version information is not available.

        """
        try:
            response = self.get(
                f'{self.PYPI_PACKAGE_NAME}/json', timeout=self.PYPI_REQUEST_TIMEOUT, hide_response_content_log=True
            )
            data = response.json()
            return data.get('info', {}).get('version')
        except Exception:
            return None

    @staticmethod
    def _parse_version(version: str) -> tuple[list[int], bool]:
        """Parse version string into components and identify if it's a pre-release.

        Extracts numeric version components and determines if the version is a pre-release
        by checking for 'dev' in the version string.

        Args:
            version: The version string to parse (e.g., '1.2.3' or '1.2.3dev4')

        Returns:
            tuple: A tuple containing:
                - List[int]: List of numeric version components
                - bool: True if this is a pre-release version, False otherwise

        """
        version_parts = [int(x) for x in re.findall(r'\d+', version)]
        is_prerelease = 'dev' in version

        return version_parts, is_prerelease

    def _should_check_update(self, is_prerelease: bool) -> bool:
        """Determine if an update check should be performed based on the last check time.

        Implements a time-based caching mechanism where update checks are performed:
        - Daily for pre-release versions
        - Weekly for stable versions

        Args:
            is_prerelease: Whether the current version is a pre-release

        Returns:
            bool: True if an update check should be performed, False otherwise

        """
        if not os.path.exists(self.cache_file):
            return True

        file_content = get_file_content(self.cache_file)
        if file_content is None:
            return True

        try:
            last_check = float(file_content.strip())
        except ValueError:
            return True

        duration = self.DAILY if is_prerelease else self.WEEKLY
        return time.time() - last_check >= duration

    def _update_last_check(self) -> None:
        """Update the timestamp of the last update check.

        Creates the cache directory if it doesn't exist and write the current timestamp
        to the cache file. Silently handle any IO errors that might occur during the process.
        """
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w', encoding='UTF-8') as f:
                f.write(str(time.time()))
        except Exception as e:
            logger.debug('Failed to update version check cache file: %s', {'file': self.cache_file}, exc_info=e)

    def check_for_update(self, current_version: str, use_cache: bool = True) -> Optional[str]:
        """Check if an update is available for the current version.

        Respects the update check frequency (daily/weekly) based on the version type

        Args:
            current_version: The current version string of the CLI
            use_cache: If True, use the cached timestamp to determine if an update check is needed

        Returns:
            str | None: The latest version string if an update is recommended,
                       None if no update is needed or if check should be skipped

        """
        current_parts, current_is_pre = self._parse_version(current_version)

        # Check if we should perform the update check based on frequency
        if use_cache and not self._should_check_update(current_is_pre):
            return None

        latest_version = self.get_latest_version()
        if not latest_version:
            return None

        # Update the last check timestamp
        use_cache and self._update_last_check()

        latest_parts, latest_is_pre = self._parse_version(latest_version)
        return _compare_versions(current_parts, latest_parts, current_is_pre, latest_is_pre, latest_version)

    def check_and_notify_update(self, current_version: str, use_cache: bool = True) -> None:
        """Check for updates and display a notification if a new version is available.

        Performs the version check and displays a formatted message with update instructions
        if a newer version is available. The message includes:
        - Current and new version numbers
        - Link to the changelog
        - Command to perform the update

        Args:
            current_version: Current version of the CLI
            use_cache: If True, use the cached timestamp to determine if an update check is needed

        """
        latest_version = self.check_for_update(current_version, use_cache)
        should_update = bool(latest_version)
        if should_update:
            update_message = (
                '\nNew release of Cycode CLI is available: '
                f'[red]{current_version}[/] -> [green]{latest_version}[/]\n'
                f'Changelog: [bright_blue]{self.GIT_CHANGELOG_URL_PREFIX}{latest_version}[/]\n'
                f'To update, run: [green]pip install --upgrade cycode[/]\n'
            )
            console.print(update_message)


version_checker = VersionChecker()
