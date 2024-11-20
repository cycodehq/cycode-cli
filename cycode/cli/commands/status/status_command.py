import dataclasses
import json
import platform
from typing import Dict

import click

from cycode import __version__
from cycode.cli.commands.auth_common import get_authorization_info
from cycode.cli.consts import PROGRAM_NAME
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.get_api_client import get_scan_cycode_client
from cycode.cyclient import logger


class CliStatusBase:
    def as_dict(self) -> Dict[str, any]:
        return dataclasses.asdict(self)

    def _get_text_message_part(self, key: str, value: any, intent: int = 0) -> str:
        message_parts = []

        intent_prefix = ' ' * intent * 2
        human_readable_key = key.replace('_', ' ').capitalize()

        if isinstance(value, dict):
            message_parts.append(f'{intent_prefix}{human_readable_key}:')
            for sub_key, sub_value in value.items():
                message_parts.append(self._get_text_message_part(sub_key, sub_value, intent=intent + 1))
        elif isinstance(value, (list, set, tuple)):
            message_parts.append(f'{intent_prefix}{human_readable_key}:')
            for index, sub_value in enumerate(value):
                message_parts.append(self._get_text_message_part(f'#{index}', sub_value, intent=intent + 1))
        else:
            message_parts.append(f'{intent_prefix}{human_readable_key}: {value}')

        return '\n'.join(message_parts)

    def as_text(self) -> str:
        message_parts = []
        for key, value in self.as_dict().items():
            message_parts.append(self._get_text_message_part(key, value))

        return '\n'.join(message_parts)

    def as_json(self) -> str:
        return json.dumps(self.as_dict())


@dataclasses.dataclass
class CliSupportedModulesStatus(CliStatusBase):
    secret_scanning: bool = False
    sca_scanning: bool = False
    iac_scanning: bool = False
    sast_scanning: bool = False
    ai_large_language_model: bool = False


@dataclasses.dataclass
class CliStatus(CliStatusBase):
    program: str
    version: str
    os: str
    arch: str
    python_version: str
    installation_id: str
    app_url: str
    api_url: str
    is_authenticated: bool
    user_id: str = None
    tenant_id: str = None
    supported_modules: CliSupportedModulesStatus = None


def get_cli_status() -> CliStatus:
    configuration_manager = ConfigurationManager()

    auth_info = get_authorization_info()
    is_authenticated = auth_info is not None

    supported_modules_status = CliSupportedModulesStatus()
    if is_authenticated:
        try:
            client = get_scan_cycode_client()
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


@click.command(short_help='Show the CLI status and exit.')
@click.pass_context
def status_command(context: click.Context) -> None:
    output = context.obj['output']

    status = get_cli_status()
    message = status.as_text()
    if output == 'json':
        message = status.as_json()

    click.echo(message, color=context.color)
    context.exit()
