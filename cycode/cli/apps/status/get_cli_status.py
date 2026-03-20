import platform
from typing import TYPE_CHECKING

from cycode import __version__
from cycode.cli.apps.activation_manager import should_report_cli_activation, report_cli_activation
from cycode.cli.apps.auth.auth_common import get_authorization_info
from cycode.cli.apps.status.models import CliStatus, CliSupportedModulesStatus
from cycode.cli.consts import PROGRAM_NAME
from cycode.cli.logger import logger
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.get_api_client import get_scan_cycode_client

if TYPE_CHECKING:
    from typer import Context


def get_cli_status(ctx: 'Context') -> CliStatus:
    configuration_manager = ConfigurationManager()

    auth_info = get_authorization_info(ctx)
    is_authenticated = auth_info is not None

    supported_modules_status = CliSupportedModulesStatus()
    if is_authenticated:
        try:
            plugin_app_name = ctx.obj.get('plugin_app_name')
            plugin_app_version = ctx.obj.get('plugin_app_version')
            client = get_scan_cycode_client(ctx)
            if should_report_cli_activation(plugin_app_name, plugin_app_version):
                report_cli_activation(client.scan_cycode_client, plugin_app_name, plugin_app_version)
            supported_modules_preferences = client.get_supported_modules_preferences()

            supported_modules_status.secret_scanning = supported_modules_preferences.secret_scanning
            supported_modules_status.sca_scanning = supported_modules_preferences.sca_scanning
            supported_modules_status.iac_scanning = supported_modules_preferences.iac_scanning
            supported_modules_status.sast_scanning = supported_modules_preferences.sast_scanning
            supported_modules_status.ai_large_language_model = supported_modules_preferences.ai_large_language_model
        except Exception as e:
            logger.debug('Failed to get supported modules preferences', exc_info=e)

    return CliStatus(
        program=PROGRAM_NAME,
        version=__version__,
        os=platform.system(),
        arch=platform.machine(),
        python_version=platform.python_version(),
        installation_id=configuration_manager.get_or_create_installation_id(),
        app_url=configuration_manager.get_cycode_app_url(),
        api_url=configuration_manager.get_cycode_api_url(),
        is_authenticated=is_authenticated,
        user_id=auth_info.user_id if auth_info else None,
        tenant_id=auth_info.tenant_id if auth_info else None,
        supported_modules=supported_modules_status,
    )
