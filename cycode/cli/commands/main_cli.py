import logging
from typing import Optional

import click

from cycode.cli.commands.auth.auth_command import auth_command
from cycode.cli.commands.configure.configure_command import configure_command
from cycode.cli.commands.ignore.ignore_command import ignore_command
from cycode.cli.commands.report.report_command import report_command
from cycode.cli.commands.scan.scan_command import scan_command
from cycode.cli.commands.version.version_command import version_command
from cycode.cli.consts import (
    CLI_CONTEXT_SETTINGS,
)
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.progress_bar import SCAN_PROGRESS_BAR_SECTIONS, get_progress_bar
from cycode.cyclient.config import set_logging_level
from cycode.cyclient.cycode_client_base import CycodeClientBase
from cycode.cyclient.models import UserAgentOptionScheme


@click.group(
    commands={
        'scan': scan_command,
        'report': report_command,
        'configure': configure_command,
        'ignore': ignore_command,
        'auth': auth_command,
        'version': version_command,
    },
    context_settings=CLI_CONTEXT_SETTINGS,
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    default=False,
    help='Show detailed logs.',
)
@click.option(
    '--no-progress-meter',
    is_flag=True,
    default=False,
    help='Do not show the progress meter.',
)
@click.option(
    '--output',
    '-o',
    default='text',
    help='Specify the output type (the default is text).',
    type=click.Choice(['text', 'json', 'table']),
)
@click.option(
    '--user-agent',
    default=None,
    help='Characteristic JSON object that lets servers identify the application.',
    type=str,
)
@click.pass_context
def main_cli(
    context: click.Context, verbose: bool, no_progress_meter: bool, output: str, user_agent: Optional[str]
) -> None:
    context.ensure_object(dict)
    configuration_manager = ConfigurationManager()

    verbose = verbose or configuration_manager.get_verbose_flag()
    context.obj['verbose'] = verbose
    if verbose:
        set_logging_level(logging.DEBUG)

    context.obj['output'] = output
    if output == 'json':
        no_progress_meter = True

    context.obj['progress_bar'] = get_progress_bar(hidden=no_progress_meter, sections=SCAN_PROGRESS_BAR_SECTIONS)

    if user_agent:
        user_agent_option = UserAgentOptionScheme().loads(user_agent)
        CycodeClientBase.enrich_user_agent(user_agent_option.user_agent_suffix)
