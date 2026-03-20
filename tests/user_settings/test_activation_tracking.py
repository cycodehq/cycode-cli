from pathlib import Path

import pytest

from cycode.cli.user_settings.config_file_manager import ConfigFileManager


@pytest.fixture()
def config_manager(tmp_path: Path) -> ConfigFileManager:
    return ConfigFileManager(tmp_path)


def test_get_last_reported_activation_versions_returns_empty_when_not_set(
    config_manager: ConfigFileManager,
) -> None:
    assert config_manager.get_last_reported_activation_versions() == {}


def test_update_and_get_last_reported_activation_version_cli(config_manager: ConfigFileManager) -> None:
    config_manager.update_last_reported_activation_version('cli', '1.10.7')

    assert config_manager.get_last_reported_activation_versions() == {'cli': '1.10.7'}


def test_update_and_get_last_reported_activation_version_plugin(config_manager: ConfigFileManager) -> None:
    config_manager.update_last_reported_activation_version('vscode_extension', '2.0.0')

    assert config_manager.get_last_reported_activation_versions() == {'vscode_extension': '2.0.0'}


def test_update_last_reported_activation_version_multiple_clients(config_manager: ConfigFileManager) -> None:
    config_manager.update_last_reported_activation_version('cli', '1.10.7')
    config_manager.update_last_reported_activation_version('vscode_extension', '2.0.0')
    config_manager.update_last_reported_activation_version('jetbrains_extension', '1.5.0')

    assert config_manager.get_last_reported_activation_versions() == {
        'cli': '1.10.7',
        'vscode_extension': '2.0.0',
        'jetbrains_extension': '1.5.0',
    }


def test_update_last_reported_activation_version_overwrites_existing(config_manager: ConfigFileManager) -> None:
    config_manager.update_last_reported_activation_version('cli', '1.10.7')
    config_manager.update_last_reported_activation_version('cli', '1.10.8')

    assert config_manager.get_last_reported_activation_versions() == {'cli': '1.10.8'}


def test_update_last_reported_activation_version_does_not_affect_other_clients(
    config_manager: ConfigFileManager,
) -> None:
    config_manager.update_last_reported_activation_version('cli', '1.10.7')
    config_manager.update_last_reported_activation_version('vscode_extension', '2.0.0')
    config_manager.update_last_reported_activation_version('cli', '1.10.8')

    assert config_manager.get_last_reported_activation_versions()['vscode_extension'] == '2.0.0'
