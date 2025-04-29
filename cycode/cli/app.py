import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
from typer import rich_utils
from typer.completion import install_callback, show_callback

from cycode import __version__
from cycode.cli.apps import ai_remediation, auth, configure, ignore, report, scan, status
from cycode.cli.cli_types import ExportTypeOption, OutputTypeOption
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


_cycode_cli_docs = 'https://github.com/cycodehq/cycode-cli/blob/main/README.md'
_cycode_cli_epilog = f"""[bold]Documentation[/]



For more details and advanced usage, visit: [link={_cycode_cli_docs}]{_cycode_cli_docs}[/link]
"""

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


def check_latest_version_on_close(ctx: typer.Context) -> None:
    output = ctx.obj.get('output')
    # don't print anything if the output is JSON
    if output == OutputTypeOption.JSON:
        return

    # we always want to check the latest version for "version" and "status" commands
    should_use_cache = ctx.invoked_subcommand not in {'version', 'status'}
    version_checker.check_and_notify_update(current_version=__version__, use_cache=should_use_cache)


def export_if_needed_on_close(ctx: typer.Context) -> None:
    printer = ctx.obj.get('console_printer')
    if printer.is_recording:
        printer.export()


_COMPLETION_RICH_HELP_PANEL = 'Completion options'
_EXPORT_RICH_HELP_PANEL = 'Export options'


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
    export_type: Annotated[
        ExportTypeOption,
        typer.Option(
            '--export-type',
            case_sensitive=False,
            help='Specify the export type. '
            'HTML and SVG will export terminal output and rely on --output option. '
            'JSON always exports JSON.',
            rich_help_panel=_EXPORT_RICH_HELP_PANEL,
        ),
    ] = ExportTypeOption.JSON,
    export_file: Annotated[
        Optional[Path],
        typer.Option(
            '--export-file',
            help='Export file. Path to the file where the export will be saved. ',
            dir_okay=False,
            writable=True,
            rich_help_panel=_EXPORT_RICH_HELP_PANEL,
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
        Optional[bool],
        typer.Option(
            '--show-completion',
            callback=show_callback,
            is_eager=True,
            expose_value=False,
            help='Show completion for the current shell, to copy it or customize the installation.',
            rich_help_panel=_COMPLETION_RICH_HELP_PANEL,
        ),
    ] = False,
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

    ctx.obj['progress_bar'] = get_progress_bar(hidden=no_progress_meter, sections=SCAN_PROGRESS_BAR_SECTIONS)

    ctx.obj['export_type'] = export_type
    ctx.obj['export_file'] = export_file
    ctx.obj['console_printer'] = ConsolePrinter(ctx)
    ctx.call_on_close(lambda: export_if_needed_on_close(ctx))

    if user_agent:
        user_agent_option = UserAgentOptionScheme().loads(user_agent)
        CycodeClientBase.enrich_user_agent(user_agent_option.user_agent_suffix)

    if not no_update_notifier:
        ctx.call_on_close(lambda: check_latest_version_on_close(ctx))
