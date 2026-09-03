import os
from pathlib import Path
from typing import Annotated, Optional

import click
import typer

from cycode.cli import consts
from cycode.cli.apps.activation_manager import report_cli_activation, should_report_cli_activation
from cycode.cli.apps.sca_options import (
    GradleAllSubProjectsOption,
    MavenSettingsFileOption,
    NoRestoreOption,
    apply_sca_restore_options_to_context,
)
from cycode.cli.apps.scan.remote_url_resolver import _try_get_git_remote_url
from cycode.cli.cli_types import ExportTypeOption, ScanTypeOption, ScaScanTypeOption, SeverityOption
from cycode.cli.consts import (
    ISSUE_DETECTED_STATUS_CODE,
    NO_ISSUES_STATUS_CODE,
    SCAN_ERROR_STATUS_CODE,
)
from cycode.cli.files_collector.file_excluder import excluder
from cycode.cli.utils import scan_utils
from cycode.cli.utils.get_api_client import get_scan_cycode_client

_EXPORT_RICH_HELP_PANEL = 'Export options'
_SCA_RICH_HELP_PANEL = 'SCA options'
_SECRET_RICH_HELP_PANEL = 'Secret options'
_BINARY_RICH_HELP_PANEL = 'Binary options'


def _single_value_callback(ctx: typer.Context, param: typer.CallbackParam, value: list) -> list:
    if len(value) > 1:
        values_str = ', '.join(str(v) for v in value)
        param_hint = '/'.join(sorted(param.opts, key=len))
        err = typer.BadParameter(
            f'Only one value can be specified per command. Got: {values_str}. Run a separate command for each value.',
            ctx=ctx,
            param_hint=param_hint,
        )
        err.exit_code = 1
        raise err
    return value


def scan_command(
    ctx: typer.Context,
    scan_type: Annotated[
        list[ScanTypeOption],
        typer.Option(
            '--scan-type',
            '-t',
            help='Specify the type of scan you wish to execute.',
            case_sensitive=False,
            callback=_single_value_callback,
        ),
    ] = (ScanTypeOption.SECRET,),
    soft_fail: Annotated[
        bool, typer.Option('--soft-fail', help='Run the scan without failing; always return a non-error status code.')
    ] = False,
    stop_on_error: Annotated[
        bool,
        typer.Option(
            '--stop-on-error',
            help='When specified, stops the scan if any file collection or restore failure occurs.',
        ),
    ] = False,
    severity_threshold: Annotated[
        SeverityOption,
        typer.Option(
            help='Show violations only for the specified level or higher.',
            case_sensitive=False,
        ),
    ] = SeverityOption.INFO,
    sync: Annotated[
        bool,
        typer.Option(
            '--sync', help='Run scan synchronously (INTERNAL FOR IDEs).', show_default='asynchronously', hidden=True
        ),
    ] = False,
    report: Annotated[
        bool,
        typer.Option(
            '--cycode-report',
            help='When specified, displays a link to the scan report in the Cycode platform in the console output.',
        ),
    ] = False,
    show_secret: Annotated[
        bool, typer.Option('--show-secret', help='Show Secrets in plain text.', rich_help_panel=_SECRET_RICH_HELP_PANEL)
    ] = False,
    sca_scan: Annotated[
        list[ScaScanTypeOption],
        typer.Option(
            help='Specify the type of SCA scan you wish to execute.',
            rich_help_panel=_SCA_RICH_HELP_PANEL,
        ),
    ] = (
        ScaScanTypeOption.PACKAGE_VULNERABILITIES,
        ScaScanTypeOption.LICENSE_COMPLIANCE,
        ScaScanTypeOption.UNMAINTAINED_PACKAGES,
    ),
    monitor: Annotated[
        bool,
        typer.Option(
            '--monitor',
            help='When specified, the scan results are recorded in the Discovery module.',
            rich_help_panel=_SCA_RICH_HELP_PANEL,
        ),
    ] = False,
    no_restore: NoRestoreOption = False,
    gradle_all_sub_projects: GradleAllSubProjectsOption = False,
    maven_settings_file: MavenSettingsFileOption = None,
    max_depth: Annotated[
        int,
        typer.Option(
            '--max-depth',
            help='Nested-archive recursion limit. An EAR containing WARs containing JARs is depth 3.',
            min=1,
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = consts.BINARY_MAX_DEPTH,
    offline: Annotated[
        bool,
        typer.Option(
            '--offline',
            help='Identify components from embedded metadata only, without resolving unknown digests. '
            'Acknowledges and silences the partial-results warning.',
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = False,
    maven_central: Annotated[
        bool,
        typer.Option(
            '--maven-central',
            help='Consult Maven Central: look archives that embedded metadata cannot identify up by SHA-1, and '
            'with --include-declared fetch parent poms to pin declared versions. Sends digests and public '
            'coordinates, never the archive itself.',
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = False,
    include_declared: Annotated[
        bool,
        typer.Option(
            '--include-declared',
            help='Also report the compile- and runtime-scope dependencies that embedded pom.xml files declare '
            'but the artifact does not ship: what a build consuming the artifact would pull in. '
            'Versions managed by a parent pom need --maven-central to resolve.',
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = False,
    include_test_scope: Annotated[
        bool,
        typer.Option(
            '--include-test-scope',
            help='With --include-declared: also report test-, provided- and system-scope declarations, which '
            'Maven never passes to a consuming build. Matches SCA tools that count every declared dependency. '
            'Each component still records its scope.',
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = False,
    include_transitive: Annotated[
        bool,
        typer.Option(
            '--include-transitive',
            help='With --include-declared and --maven-central: follow each declared dependency to the '
            'dependencies its own pom declares, the way a Maven build would, and report those too.',
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = False,
    project_name: Annotated[
        Optional[str],
        typer.Option(
            '--project-name',
            help='Override the platform identity when the artifact is detached from its source repository.',
            show_default='inferred from the Git remote, else the artifact filename',
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = None,
    include_binaries: Annotated[
        bool,
        typer.Option(
            '--include-binaries',
            help='On `scan path` only. Extract and scan any Java archives encountered during the walk.',
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = False,
    keep_bom: Annotated[
        bool,
        typer.Option(
            '--keep-bom',
            help='Write the synthesised CycloneDX document beside each artifact for inspection.',
            rich_help_panel=_BINARY_RICH_HELP_PANEL,
        ),
    ] = False,
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
    ] = None,
    export_file: Annotated[
        Optional[Path],
        typer.Option(
            '--export-file',
            help='Export file. Path to the file where the export will be saved.',
            dir_okay=False,
            writable=True,
            rich_help_panel=_EXPORT_RICH_HELP_PANEL,
        ),
    ] = None,
) -> None:
    """:mag: [bold cyan]Scan code for vulnerabilities (Secrets, IaC, SCA, SAST).[/]

    This command scans your code for various types of security issues, including:
    * [yellow]Secrets:[/] Hardcoded credentials and sensitive information.
    * [dodger_blue1]Infrastructure as Code (IaC):[/] Misconfigurations in Terraform, CloudFormation, etc.
    * [green]Software Composition Analysis (SCA):[/] Vulnerabilities and license issues in dependencies.
    * [magenta]Static Application Security Testing (SAST):[/] Code quality and security flaws.

    Example usage:
    * `cycode scan path <PATH>`: Scan a specific local directory or file.
    * `cycode scan repository <PATH>`: Scan Git related files in a local Git repository.
    * `cycode scan commit-history <PATH>`: Scan the commit history of a local Git repository.
    * `cycode scan -t sca binary <PATH>`: Scan a built Java artifact (JAR, WAR, EAR, Spring Boot).

    """
    if export_file and export_type is None:
        raise typer.BadParameter(
            'Export type must be specified when --export-file is provided.',
            param_hint='--export-type',
        )
    if export_type and export_file is None:
        raise typer.BadParameter(
            'Export file must be specified when --export-type is provided.',
            param_hint='--export-file',
        )
    if offline and maven_central:
        raise typer.BadParameter(
            '--offline identifies from embedded metadata only; it cannot be combined with --maven-central.',
            param_hint='--maven-central',
        )
    if include_test_scope and not include_declared:
        raise typer.BadParameter(
            '--include-test-scope widens what --include-declared reports; it does nothing on its own.',
            param_hint='--include-test-scope',
        )
    if include_transitive and not (include_declared and maven_central):
        raise typer.BadParameter(
            '--include-transitive follows declared dependencies through their poms on Maven Central; '
            'it needs both --include-declared and --maven-central.',
            param_hint='--include-transitive',
        )

    # _single_value_callback validated exactly one value was provided; unwrap from list
    scan_type = scan_type[0]

    ctx.obj['show_secret'] = show_secret
    ctx.obj['soft_fail'] = soft_fail
    ctx.obj['stop_on_error'] = stop_on_error
    ctx.obj['scan_type'] = scan_type
    ctx.obj['sync'] = sync
    ctx.obj['severity_threshold'] = severity_threshold
    ctx.obj['monitor'] = monitor
    ctx.obj['report'] = report
    ctx.obj['binary_max_depth'] = max_depth
    ctx.obj['offline'] = offline
    ctx.obj['maven_central'] = maven_central
    ctx.obj['include_declared'] = include_declared
    ctx.obj['include_test_scope'] = include_test_scope
    ctx.obj['include_transitive'] = include_transitive
    ctx.obj['project_name'] = project_name
    ctx.obj['keep_bom'] = keep_bom
    ctx.obj['include_binaries'] = include_binaries
    apply_sca_restore_options_to_context(ctx, no_restore, gradle_all_sub_projects, maven_settings_file)

    scan_client = get_scan_cycode_client(ctx)
    ctx.obj['client'] = scan_client

    plugin_app_name = ctx.obj.get('plugin_app_name')
    plugin_app_version = ctx.obj.get('plugin_app_version')
    if should_report_cli_activation(plugin_app_name, plugin_app_version):
        report_cli_activation(scan_client.scan_cycode_client, plugin_app_name, plugin_app_version)

    # Get remote URL from current working directory
    remote_url = _try_get_git_remote_url(os.getcwd())

    remote_scan_config = scan_client.get_scan_configuration_safe(scan_type, remote_url)
    if remote_scan_config:
        excluder.apply_scan_config(str(scan_type), remote_scan_config)

    ctx.obj['scan_config'] = remote_scan_config

    if export_type and export_file:
        console_printer = ctx.obj['console_printer']
        console_printer.enable_recording(export_type, export_file)

    _sca_scan_to_context(ctx, sca_scan)


def _sca_scan_to_context(ctx: typer.Context, sca_scan_user_selected: list[str]) -> None:
    for sca_scan_option_selected in sca_scan_user_selected:
        ctx.obj[sca_scan_option_selected] = True


@click.pass_context
def scan_command_result_callback(ctx: click.Context, *_, **__) -> None:
    ctx.obj['scan_finalized'] = True

    progress_bar = ctx.obj.get('progress_bar')
    if progress_bar:
        progress_bar.stop()

    if ctx.obj['soft_fail']:
        raise typer.Exit(0)

    exit_code = NO_ISSUES_STATUS_CODE
    if ctx.obj.get('did_fail') and ctx.obj.get('stop_on_error'):
        exit_code = SCAN_ERROR_STATUS_CODE
    elif scan_utils.is_scan_failed(ctx):
        exit_code = ISSUE_DETECTED_STATUS_CODE

    raise typer.Exit(exit_code)
