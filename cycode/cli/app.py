import logging
from typing import Annotated, Optional

import typer

from cycode import __version__
from cycode.cli.apps import ai_remediation, auth, configure, ignore, report, scan, status
from cycode.cli.cli_types import OutputTypeOption
from cycode.cli.consts import CLI_CONTEXT_SETTINGS
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.progress_bar import SCAN_PROGRESS_BAR_SECTIONS, get_progress_bar
from cycode.cli.utils.sentry import add_breadcrumb, init_sentry
from cycode.cli.utils.version_checker import version_checker
from cycode.cyclient.config import set_logging_level
from cycode.cyclient.cycode_client_base import CycodeClientBase
from cycode.cyclient.models import UserAgentOptionScheme

app = typer.Typer(
    pretty_exceptions_show_locals=False,
    pretty_exceptions_short=True,
    context_settings=CLI_CONTEXT_SETTINGS,
    rich_markup_mode='rich',
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
    version_checker.check_and_notify_update(
        current_version=__version__, use_color=ctx.color, use_cache=should_use_cache
    )


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
    ] = OutputTypeOption.TEXT,
    user_agent: Annotated[
        Optional[str],
        typer.Option(hidden=True, help='Characteristic JSON object that lets servers identify the application.'),
    ] = None,
) -> None:
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

    if user_agent:
        user_agent_option = UserAgentOptionScheme().loads(user_agent)
        CycodeClientBase.enrich_user_agent(user_agent_option.user_agent_suffix)

    if not no_update_notifier:
        ctx.call_on_close(lambda: check_latest_version_on_close(ctx))
