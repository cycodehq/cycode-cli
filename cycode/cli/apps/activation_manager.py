from typing import TYPE_CHECKING, Optional

from cycode import __version__
from cycode.cli.config import configuration_manager
from cycode.cyclient.cli_activation_client import CliActivationClient
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cyclient.cycode_client_base import CycodeClientBase

logger = get_logger('Activation Manager')

_CLI_CLIENT_NAME = 'cli'


def _get_client_and_version(
    plugin_app_name: Optional[str], plugin_app_version: Optional[str]
) -> tuple[str, str]:
    return plugin_app_name or _CLI_CLIENT_NAME, plugin_app_version or __version__


def should_report_cli_activation(
    plugin_app_name: Optional[str] = None,
    plugin_app_version: Optional[str] = None,
) -> bool:
    client, version = _get_client_and_version(plugin_app_name, plugin_app_version)
    return configuration_manager.get_last_reported_activation_version(client) != version


def report_cli_activation(
    cycode_client: 'CycodeClientBase',
    plugin_app_name: Optional[str] = None,
    plugin_app_version: Optional[str] = None,
) -> None:
    """Report CLI/IDE activation to the backend if the (client, version) pair is new.

    Failures are swallowed — activation tracking is non-critical.
    """
    try:
        client, version = _get_client_and_version(plugin_app_name, plugin_app_version)

        if configuration_manager.get_last_reported_activation_version(client) == version:
            return

        CliActivationClient(cycode_client).report_activation()
        configuration_manager.update_last_reported_activation_version(client, version)
    except Exception:
        logger.debug('Failed to report CLI activation', exc_info=True)
