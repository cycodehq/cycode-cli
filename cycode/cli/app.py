import importlib
import logging
import sys
from typing import Annotated, Optional

import click
import typer
from typer import rich_utils
from typer._completion_classes import completion_init
from typer._completion_shared import Shells
from typer.completion import install_callback, show_callback

from cycode import __version__
from cycode.cli.apps.api import get_platform_group
from cycode.cli.cli_types import OutputTypeOption
from cycode.cli.consts import CLI_CONTEXT_SETTINGS
from cycode.cli.printers import ConsolePrinter
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.progress_bar import SCAN_PROGRESS_BAR_SECTIONS, get_progress_bar
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

# Top-level subcommand → module providing its Typer app. Peeking at sys.argv
# lets us import only the invoked subapp on the hot path (e.g.
# `cycode ai-guardrails scan`), skipping ~300ms of unrelated imports.
_SUBAPP_MODULES: dict[str, str] = {
    'ai-guardrails': 'cycode.cli.apps.ai_guardrails',
    'ai-remediation': 'cycode.cli.apps.ai_remediation',
    'auth': 'cycode.cli.apps.auth',
    'configure': 'cycode.cli.apps.configure',
    'ignore': 'cycode.cli.apps.ignore',
    'report': 'cycode.cli.apps.report',
    'import': 'cycode.cli.apps.report_import',
    'scan': 'cycode.cli.apps.scan',
    'status': 'cycode.cli.apps.status',
}
if sys.version_info >= (3, 10):
    _SUBAPP_MODULES['mcp'] = 'cycode.cli.apps.mcp'

# Aliases: alternate spellings that resolve to a primary subcommand key.
_SUBAPP_ALIASES: dict[str, str] = {
    'ai_remediation': 'ai-remediation',  # backward-compat underscore form
    'version': 'status',
}

# Root-level options that consume a following value; argv-peek must skip past
# both the option and its value when scanning for the first positional arg.
_ROOT_OPTS_WITH_VALUE = frozenset(
    {
        '--output',
        '-o',
        '--user-agent',
        '--client-secret',
        '--client-id',
        '--id-token',
        '--show-completion',
    }
)


def _detect_invocation() -> tuple[Optional[str], Optional[str]]:
    """Return (top-level-subapp, second-level-subcommand) parsed from sys.argv.

    Both values may be None: when no positional arg matches a known subapp,
    or when the user only provided a top-level subcommand.
    """
    positionals = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _ROOT_OPTS_WITH_VALUE:
            i += 2
        elif arg.startswith('-'):
            # Any flag form: short, long, --key=value, or '--' marker. Skip the token only.
            i += 1
        else:
            positionals.append(arg)
            if len(positionals) >= 2:
                break
            i += 1
    subapp = positionals[0] if positionals else None
    subapp = _SUBAPP_ALIASES.get(subapp, subapp)
    if subapp not in _SUBAPP_MODULES:
        return None, None
    subcommand = positionals[1] if len(positionals) >= 2 else None
    return subapp, subcommand


# Computed once at import; reused by lazy registration and the version-checker skip.
_INVOKED_SUBAPP, _INVOKED_SUBCOMMAND = _detect_invocation()


def _register_subapps(only: Optional[str]) -> None:
    if only is not None:
        app.add_typer(importlib.import_module(_SUBAPP_MODULES[only]).app)
        return
    # Cold path (--help, completion, unknown subcommand): load all modules so
    # root help lists everything. Deduplicate since aliases share modules.
    for module_path in dict.fromkeys(_SUBAPP_MODULES.values()):
        app.add_typer(importlib.import_module(module_path).app)


_register_subapps(_INVOKED_SUBAPP)

# Register the `platform` command group (dynamically built from the OpenAPI spec).
# The group itself is constructed cheaply at import time; the spec is only fetched
# when the user actually invokes `cycode platform ...`. Unrelated commands like
# `cycode scan` and `cycode status` never trigger a spec fetch.
#
# Typer doesn't support adding native Click groups directly, so we monkey-patch
# typer.main.get_group to inject our `platform` group into the resolved Click group.
# The `app_typer is app` guard ensures we only modify our own app.
_platform_group = get_platform_group()
_original_get_group = typer.main.get_group


def _get_group_with_platform(app_typer: typer.Typer) -> click.Group:
    group = _original_get_group(app_typer)
    if app_typer is app and _platform_group.name not in group.commands:
        group.add_command(_platform_group, _platform_group.name)
    return group


typer.main.get_group = _get_group_with_platform


def check_latest_version_on_close(ctx: typer.Context) -> None:
    # Skip on `cycode ai-guardrails scan` — it emits JSON to stdout, so an
    # upgrade notice would corrupt the response. Human-driven sibling commands
    # (install, uninstall, status, session-start) still get the notice.
    if (_INVOKED_SUBAPP, _INVOKED_SUBCOMMAND) == ('ai-guardrails', 'scan'):
        return

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
    id_token: Annotated[
        Optional[str],
        typer.Option(
            help='Specify a Cycode OIDC ID token for this specific scan execution.',
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
    ctx.obj['id_token'] = id_token

    ctx.obj['progress_bar'] = get_progress_bar(hidden=no_progress_meter, sections=SCAN_PROGRESS_BAR_SECTIONS)

    ctx.obj['console_printer'] = ConsolePrinter(ctx)
    ctx.call_on_close(lambda: export_if_needed_on_close(ctx))

    if user_agent:
        user_agent_option = UserAgentOptionScheme().loads(user_agent)
        CycodeClientBase.enrich_user_agent(user_agent_option.user_agent_suffix)
        ctx.obj['plugin_app_name'] = user_agent_option.app_name
        ctx.obj['plugin_app_version'] = user_agent_option.app_version

    if not no_update_notifier:
        ctx.call_on_close(lambda: check_latest_version_on_close(ctx))
