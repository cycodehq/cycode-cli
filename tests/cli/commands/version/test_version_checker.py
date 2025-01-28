import time
from typing import TYPE_CHECKING, Optional
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from cycode.cli.commands.version.version_checker import VersionChecker


@pytest.fixture
def version_checker() -> 'VersionChecker':
    return VersionChecker()


@pytest.fixture
def version_checker_cached(tmp_path: 'Path', version_checker: 'VersionChecker') -> 'VersionChecker':
    version_checker.cache_file = tmp_path / '.version_check'
    return version_checker


class TestVersionChecker:
    def test_parse_version_stable(self, version_checker: 'VersionChecker') -> None:
        version = '1.2.3'
        parts, is_pre = version_checker._parse_version(version)

        assert parts == [1, 2, 3]
        assert not is_pre

    def test_parse_version_prerelease(self, version_checker: 'VersionChecker') -> None:
        version = '1.2.3dev4'
        parts, is_pre = version_checker._parse_version(version)

        assert parts == [1, 2, 3, 4]
        assert is_pre

    def test_parse_version_complex(self, version_checker: 'VersionChecker') -> None:
        version = '1.2.3.dev4.post5'
        parts, is_pre = version_checker._parse_version(version)

        assert parts == [1, 2, 3, 4, 5]
        assert is_pre

    def test_should_check_update_no_cache(self, version_checker_cached: 'VersionChecker') -> None:
        assert version_checker_cached._should_check_update(is_prerelease=False) is True

    def test_should_check_update_invalid_cache(self, version_checker_cached: 'VersionChecker') -> None:
        version_checker_cached.cache_file.write_text('invalid')
        assert version_checker_cached._should_check_update(is_prerelease=False) is True

    def test_should_check_update_expired(self, version_checker_cached: 'VersionChecker') -> None:
        # Write a timestamp from 8 days ago
        old_time = time.time() - (8 * 24 * 60 * 60)
        version_checker_cached.cache_file.write_text(str(old_time))

        assert version_checker_cached._should_check_update(is_prerelease=False) is True

    def test_should_check_update_not_expired(self, version_checker_cached: 'VersionChecker') -> None:
        # Write a recent timestamp
        version_checker_cached.cache_file.write_text(str(time.time()))

        assert version_checker_cached._should_check_update(is_prerelease=False) is False

    def test_should_check_update_prerelease_daily(self, version_checker_cached: 'VersionChecker') -> None:
        # Write a timestamp from 25 hours ago
        old_time = time.time() - (25 * 60 * 60)
        version_checker_cached.cache_file.write_text(str(old_time))

        assert version_checker_cached._should_check_update(is_prerelease=True) is True

    @pytest.mark.parametrize(
        'current_version, latest_version, expected_result',
        [
            # Stable version comparisons
            ('1.2.3', '1.2.4', '1.2.4'),  # Higher patch version
            ('1.2.3', '1.3.0', '1.3.0'),  # Higher minor version
            ('1.2.3', '2.0.0', '2.0.0'),  # Higher major version
            ('1.2.3', '1.2.3', None),  # Same version
            ('1.2.4', '1.2.3', None),  # Current higher than latest
            # Pre-release version comparisons
            ('1.2.3dev1', '1.2.3', '1.2.3'),  # Pre-release to stable
            ('1.2.3', '1.2.4dev1', None),  # Stable to pre-release
            ('1.2.3dev1', '1.2.3dev2', '1.2.3dev2'),  # Pre-release to higher pre-release
            ('1.2.3dev2', '1.2.3dev1', None),  # Pre-release to lower pre-release
            # Edge cases
            ('1.0.0dev1', '1.0.0', '1.0.0'),  # Pre-release to same version stable
            ('2.0.0', '2.0.0dev1', None),  # Stable to same version pre-release
            ('2.2.1.dev4', '2.2.0', None)  # Pre-release to lower stable
        ],
    )
    def test_check_for_update_scenarios(
        self,
        version_checker_cached: 'VersionChecker',
        current_version: str,
        latest_version: str,
        expected_result: Optional[str],
    ) -> None:
        with patch.multiple(
            version_checker_cached,
            _should_check_update=MagicMock(return_value=True),
            get_latest_version=MagicMock(return_value=latest_version),
            _update_last_check=MagicMock(),
        ):
            result = version_checker_cached.check_for_update(current_version)
            assert result == expected_result

    def test_get_latest_version_success(self, version_checker: 'VersionChecker') -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {'info': {'version': '1.2.3'}}
        with patch.object(version_checker, 'get', return_value=mock_response):
            assert version_checker.get_latest_version() == '1.2.3'

    def test_get_latest_version_failure(self, version_checker: 'VersionChecker') -> None:
        with patch.object(version_checker, 'get', side_effect=Exception):
            assert version_checker.get_latest_version() is None

    def test_update_last_check(self, version_checker_cached: 'VersionChecker') -> None:
        version_checker_cached._update_last_check()
        assert version_checker_cached.cache_file.exists()

        timestamp = float(version_checker_cached.cache_file.read_text().strip())
        assert abs(timestamp - time.time()) < 1  # Should be within 1 second

    def test_update_last_check_permission_error(self, version_checker_cached: 'VersionChecker') -> None:
        with patch('builtins.open', side_effect=IOError):
            version_checker_cached._update_last_check()
            # Should not raise an exception
