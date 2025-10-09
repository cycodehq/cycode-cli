import pytest

from cycode.cli import consts
from cycode.cli.files_collector.file_excluder import Excluder, _is_file_relevant_for_sca_scan

class TestIsFileRelevantForScaScan:
    """Test the SCA path exclusion logic."""

    def test_files_in_excluded_directories_should_be_excluded(self) -> None:
        """Test that files inside excluded directories are properly excluded."""

        # Test node_modules exclusion
        assert _is_file_relevant_for_sca_scan('project/node_modules/package/index.js') is False
        assert _is_file_relevant_for_sca_scan('/project/node_modules/package.json') is False
        assert _is_file_relevant_for_sca_scan('deep/nested/node_modules/lib/file.txt') is False

        # Test .gradle exclusion
        assert _is_file_relevant_for_sca_scan('project/.gradle/wrapper/gradle-wrapper.jar') is False
        assert _is_file_relevant_for_sca_scan('/home/user/.gradle/caches/modules.xml') is False

        # Test venv exclusion
        assert _is_file_relevant_for_sca_scan('project/venv/lib/python3.8/site-packages/module.py') is False
        assert _is_file_relevant_for_sca_scan('/home/user/venv/bin/activate') is False

        # Test __pycache__ exclusion
        assert _is_file_relevant_for_sca_scan('src/__pycache__/module.cpython-38.pyc') is False
        assert _is_file_relevant_for_sca_scan('project/utils/__pycache__/helper.pyc') is False

    def test_files_with_excluded_names_in_filename_should_be_included(self) -> None:
        """Test that files containing excluded directory names in their filename are NOT excluded."""

        # These should be INCLUDED because the excluded terms are in the filename, not directory path
        assert _is_file_relevant_for_sca_scan('project/build.gradle') is True
        assert _is_file_relevant_for_sca_scan('project/gradlew') is True
        assert _is_file_relevant_for_sca_scan('app/node_modules_backup.txt') is True
        assert _is_file_relevant_for_sca_scan('src/venv_setup.py') is True
        assert _is_file_relevant_for_sca_scan('utils/pycache_cleaner.py') is True
        assert _is_file_relevant_for_sca_scan('config/gradle_config.xml') is True

    def test_files_with_excluded_extensions_in_should_be_included(self) -> None:
        """Test that files containing excluded extensions are NOT excluded."""
        excluder = Excluder()
        # These should be INCLUDED because the excluded terms are in the filename
        assert excluder._is_relevant_file_to_scan_common('iac','project/cfg/Dockerfile') is True
        assert excluder._is_relevant_file_to_scan_common('iac','project/cfg/build.tf') is True
        assert excluder._is_relevant_file_to_scan_common('iac', 'project/cfg/build.tf.json') is True
        assert excluder._is_relevant_file_to_scan_common('iac', 'project/cfg/config.json') is True
        assert excluder._is_relevant_file_to_scan_common('iac', 'project/cfg/config.yaml') is True
        assert excluder._is_relevant_file_to_scan_common('iac', 'project/cfg/config.yml') is True
        # These should be EXCLUDED because the excluded terms are not in the filename
        assert excluder._is_relevant_file_to_scan_common('iac','project/cfg/build') is False
        assert excluder._is_relevant_file_to_scan_common('iac', 'project/cfg/build') is False
        assert excluder._is_relevant_file_to_scan_common('iac', 'project/cfg/Dockerfile.txt') is False
        assert excluder._is_relevant_file_to_scan_common('iac', 'project/cfg/config.ini') is False

    def test_files_in_regular_directories_should_be_included(self) -> None:
        """Test that files in regular directories (not excluded) are included."""

        assert _is_file_relevant_for_sca_scan('project/src/main.py') is True
        assert _is_file_relevant_for_sca_scan('app/components/button.tsx') is True
        assert _is_file_relevant_for_sca_scan('/home/user/project/package.json') is True
        assert _is_file_relevant_for_sca_scan('build/dist/app.js') is True
        assert _is_file_relevant_for_sca_scan('tests/unit/test_utils.py') is True

    def test_multiple_excluded_directories_in_path(self) -> None:
        """Test paths that contain multiple excluded directories."""

        # Should be excluded if ANY directory in the path is excluded
        assert _is_file_relevant_for_sca_scan('project/venv/lib/node_modules/package.json') is False
        assert _is_file_relevant_for_sca_scan('app/node_modules/dep/.gradle/build.xml') is False
        assert _is_file_relevant_for_sca_scan('src/__pycache__/nested/venv/file.py') is False

    def test_absolute_vs_relative_paths(self) -> None:
        """Test both absolute and relative path formats."""

        # Relative paths
        assert _is_file_relevant_for_sca_scan('node_modules/package.json') is False
        assert _is_file_relevant_for_sca_scan('src/app.py') is True

        # Absolute paths
        assert _is_file_relevant_for_sca_scan('/home/user/project/node_modules/lib.js') is False
        assert _is_file_relevant_for_sca_scan('/home/user/project/src/main.py') is True

    def test_edge_cases(self) -> None:
        """Test edge cases and boundary conditions."""

        # Empty string should be considered relevant (no path to exclude)
        assert _is_file_relevant_for_sca_scan('') is True
        # Single filename without a directory
        assert _is_file_relevant_for_sca_scan('package.json') is True
        # Root-level excluded directory
        assert _is_file_relevant_for_sca_scan('/node_modules/package.json') is False
        # Excluded directory as part of the filename but in allowed directory
        assert _is_file_relevant_for_sca_scan('src/my_node_modules_file.js') is True

    def test_case_sensitivity(self) -> None:
        """Test that directory matching is case-sensitive."""

        # Excluded directories are lowercase, so uppercase versions should be included
        assert _is_file_relevant_for_sca_scan('project/NODE_MODULES/package.json') is True
        assert _is_file_relevant_for_sca_scan('project/Node_Modules/lib.js') is True
        assert _is_file_relevant_for_sca_scan('project/VENV/lib/module.py') is True

        # But exact case matches should be excluded
        assert _is_file_relevant_for_sca_scan('project/node_modules/package.json') is False
        assert _is_file_relevant_for_sca_scan('project/venv/lib/module.py') is False

    def test_nested_excluded_directories(self) -> None:
        """Test deeply nested directory structures with excluded directories."""

        # Deep nesting should still work
        deep_path = 'a/b/c/d/e/f/g/node_modules/h/i/j/package.json'
        assert _is_file_relevant_for_sca_scan(deep_path) is False

        # Multiple levels of excluded directories
        multi_excluded = 'project/node_modules/package/venv/lib/__pycache__/module.pyc'
        assert _is_file_relevant_for_sca_scan(multi_excluded) is False

    @pytest.mark.parametrize('excluded_dir', consts.SCA_EXCLUDED_FOLDER_IN_PATH)
    def test_parametrized_excluded_directories(self, excluded_dir: str) -> None:
        """Parametrized test to ensure all excluded directories work correctly."""

        # File inside excluded directory should be excluded
        excluded_path = f'project/{excluded_dir}/file.txt'
        assert _is_file_relevant_for_sca_scan(excluded_path) is False

        # File with excluded directory name in filename should be included
        included_path = f'project/src/{excluded_dir}_config.txt'
        assert _is_file_relevant_for_sca_scan(included_path) is True
