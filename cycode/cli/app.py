import logging
import sys
from typing import Annotated, Optional

import typer
from typer import rich_utils
from typer._completion_classes import completion_init
from typer._completion_shared import Shells
from typer.completion import install_callback, show_callback

from cycode import __version__
from cycode.cli.apps import ai_remediation, auth, configure, ignore, report, scan, status

if sys.version_info >= (3, 10):
    from cycode.cli.apps import mcp

from cycode.cli.cli_types import OutputTypeOption
from cycode.cli.consts import CLI_CONTEXT_SETTINGS
from cycode.cli.printers import ConsolePrinter
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.progress_bar import SCAN_PROGRESS_BAR_SECTIONS, get_progress_bar
from cycode.cli.utils.sentry import add_breadcrumb, init_sentry
from cycode.cli.utils.version_checker import version_checker
from cycode.cyclient.cycode_client_base import CycodeClientBase
from cycode.cyclient.models import UserAgentOptionScheme
from cycode.logger import set_logging_level

# By default, it uses dim style which is hard to read with the combination of color from RICH_HELP
rich_utils.STYLE_ERRORS_SUGGESTION = 'bold'
# By default, it uses blue color which is too dark for some terminals
rich_utils.RICH_HELP = "Try [cyan]'{command_path} {help_option}'[/] for help."

completion_init()  # DO NOT TOUCH; this is required for the completion to work properly

_cycode_cli_docs = 'https://github.com/cycodehq/cycode-cli/blob/main/README.md'
_cycode_cli_epilog = f'[bold]Documentation:[/] [link={_cycode_cli_docs}]{_cycode_cli_docs}[/link]'

app = typer.Typer(
    pretty_exceptions_show_locals=False,
    pretty_exceptions_short=True,
    context_settings=CLI_CONTEXT_SETTINGS,
    epilog=_cycode_cli_epilog,
    rich_markup_mode='rich',
    no_args_is_help=True,
    add_completion=False,  # we add it manually to control the rich help panel
)

app.add_typer(ai_remediation.app)
app.add_typer(auth.app)
app.add_typer(configure.app)
app.add_typer(ignore.app)
app.add_typer(report.app)
app.add_typer(scan.app)
app.add_typer(status.app)
if sys.version_info >= (3, 10):
    app.add_typer(mcp.app)


def check_latest_version_on_close(ctx: typer.Context) -> None:
    output = ctx.obj.get('output')
    # don't print anything if the output is JSON
    if output == OutputTypeOption.JSON:
        return

    # we always want to check the latest version for "version" and "status" commands
    should_use_cache = ctx.invoked_subcommand not in {'version', 'status'}
    version_checker.check_and_notify_update(current_version=__version__, use_cache=should_use_cache)


def export_if_needed_on_close(ctx: typer.Context) -> None:
    scan_finalized = ctx.obj.get('scan_finalized')
    printer = ctx.obj.get('console_printer')
    if scan_finalized and printer.is_recording:
        printer.export()


_AUTH_RICH_HELP_PANEL = 'Authentication options'
_COMPLETION_RICH_HELP_PANEL = 'Completion options'


@app.callback()
def app_callback(
    ctx: typer.Context,
    verbose: Annotated[bool, typer.Option('--verbose', '-v', help='Show detailed logs.')] = False,
    no_progress_meter: Annotated[
        bool, typer.Option('--no-progress-meter', help='Do not show the progress meter.')
    ] = False,
    no_update_notifier: Annotated[
        bool, typer.Option('--no-update-notifier', help='Do not check CLI for updates.')
    ] = False,
    output: Annotated[
        OutputTypeOption, typer.Option('--output', '-o', case_sensitive=False, help='Specify the output type.')
    ] = OutputTypeOption.RICH,
    user_agent: Annotated[
        Optional[str],
        typer.Option(hidden=True, help='Characteristic JSON object that lets servers identify the application.'),
    ] = None,
    client_secret: Annotated[
        Optional[str],
        typer.Option(
            help='Specify a Cycode client secret for this specific scan execution.',
            rich_help_panel=_AUTH_RICH_HELP_PANEL,
        ),
    ] = None,
    client_id: Annotated[
        Optional[str],
        typer.Option(
            help='Specify a Cycode client ID for this specific scan execution.',
            rich_help_panel=_AUTH_RICH_HELP_PANEL,
        ),
    ] = None,
    _: Annotated[
        Optional[bool],
        typer.Option(
            '--install-completion',
            callback=install_callback,
            is_eager=True,
            expose_value=False,
            help='Install completion for the current shell.',
            rich_help_panel=_COMPLETION_RICH_HELP_PANEL,
        ),
    ] = False,
    __: Annotated[
        Shells,  # the choice is required for Homebrew to be able to install the completion
        typer.Option(
            '--show-completion',
            callback=show_callback,
            is_eager=True,
            expose_value=False,
            show_default=False,
            help='Show completion for the specified shell, to copy it or customize the installation.',
            rich_help_panel=_COMPLETION_RICH_HELP_PANEL,
        ),
    ] = None,
) -> None:
    """[bold cyan]Cycode CLI - Command Line Interface for Cycode.[/]"""
    init_sentry()
    add_breadcrumb('cycode')

    ctx.ensure_object(dict)
    configuration_manager = ConfigurationManager()

    verbose = verbose or configuration_manager.get_verbose_flag()
    ctx.obj['verbose'] = verbose
    if verbose:
        set_logging_level(logging.DEBUG)

    ctx.obj['output'] = output
    if output == OutputTypeOption.JSON:
        no_progress_meter = True

    ctx.obj['client_id'] = client_id
    ctx.obj['client_secret'] = client_secret

    ctx.obj['progress_bar'] = get_progress_bar(hidden=no_progress_meter, sections=SCAN_PROGRESS_BAR_SECTIONS)

    ctx.obj['console_printer'] = ConsolePrinter(ctx)
    ctx.call_on_close(lambda: export_if_needed_on_close(ctx))

    if user_agent:
        user_agent_option = UserAgentOptionScheme().loads(user_agent)
        CycodeClientBase.enrich_user_agent(user_agent_option.user_agent_suffix)

    if not no_update_notifier:
        ctx.call_on_close(lambda: check_latest_version_on_close(ctx))
