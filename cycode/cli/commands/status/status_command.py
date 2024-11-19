import dataclasses
import json
import platform

import click

from cycode import __version__
from cycode.cli.commands.auth_common import get_authorization_info
from cycode.cli.consts import PROGRAM_NAME
from cycode.cli.user_settings.configuration_manager import ConfigurationManager


@dataclasses.dataclass
class Status:
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

    def as_text(self) -> str:
        message_parts = []
        for key, value in dataclasses.asdict(self).items():
            human_readable_key = key.replace('_', ' ').capitalize()
            message_parts.append(f'{human_readable_key}: {value}')

        return '\n'.join(message_parts)

    def as_json(self) -> str:
        return json.dumps(dataclasses.asdict(self))


def get_cli_status() -> Status:
    configuration_manager = ConfigurationManager()
    auth_info = get_authorization_info()

    # TODO: Add supported modules; add AI status

    return Status(
        program=PROGRAM_NAME,
        version=__version__,
        os=platform.system(),
        arch=platform.machine(),
        python_version=platform.python_version(),
        installation_id=configuration_manager.get_or_create_installation_id(),
        app_url=configuration_manager.get_cycode_app_url(),
        api_url=configuration_manager.get_cycode_api_url(),
        is_authenticated=auth_info is not None,
        user_id=auth_info.user_id if auth_info else None,
        tenant_id=auth_info.tenant_id if auth_info else None,
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
