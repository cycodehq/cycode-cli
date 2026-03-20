from typing import TYPE_CHECKING, Optional

from cycode import __version__
from cycode.cli.config import configuration_manager
from cycode.cyclient.cli_activation_client import CliActivationClient
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cyclient.cycode_client_base import CycodeClientBase

logger = get_logger('Activation Manager')

_CLI_CLIENT_NAME = 'cli'


def try_report_activation(
    cycode_client: 'CycodeClientBase',
    plugin_app_name: Optional[str] = None,
    plugin_app_version: Optional[str] = None,
) -> None:
    """Report CLI/IDE activation to the backend if the (client, version) pair is new.

    Failures are swallowed — activation tracking is non-critical.
    """
    try:
        client = plugin_app_name or _CLI_CLIENT_NAME
        version = plugin_app_version or __version__

        if configuration_manager.get_last_reported_activation_version(client) == version:
            return

        CliActivationClient(cycode_client).report_activation()
        configuration_manager.update_last_reported_activation_version(client, version)
    except Exception:
        logger.debug('Failed to report CLI activation', exc_info=True)
