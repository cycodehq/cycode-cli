import re
from typing import Annotated, Optional

import click
import typer

from cycode.cli import consts
from cycode.cli.cli_types import ScanTypeOption
from cycode.cli.config import configuration_manager
from cycode.cli.logger import logger
from cycode.cli.utils.path_utils import get_absolute_path, is_path_exists
from cycode.cli.utils.sentry import add_breadcrumb
from cycode.cli.utils.string_utils import hash_string_to_sha256


def _is_package_pattern_valid(package: str) -> bool:
    return re.search('^[^@]+@[^@]+$', package) is not None


def ignore_command(  # noqa: C901
    by_value: Annotated[
        Optional[str], typer.Option(help='Ignore a specific value while scanning for Secrets.', show_default=False)
    ] = None,
    by_sha: Annotated[
        Optional[str],
        typer.Option(
            help='Ignore a specific SHA512 representation of a string while scanning for Secrets.', show_default=False
        ),
    ] = None,
    by_path: Annotated[
        Optional[str],
        typer.Option(help='Avoid scanning a specific path. You`ll need to specify the scan type.', show_default=False),
    ] = None,
    by_rule: Annotated[
        Optional[str],
        typer.Option(
            help='Ignore scanning a specific secret rule ID or IaC rule ID. You`ll to specify the scan type.',
            show_default=False,
        ),
    ] = None,
    by_package: Annotated[
        Optional[str],
        typer.Option(
            help='Ignore scanning a specific package version while running an SCA scan. '
            'Expected pattern: name@version.',
            show_default=False,
        ),
    ] = None,
    by_cve: Annotated[
        Optional[str],
        typer.Option(
            help='Ignore scanning a specific CVE while running an SCA scan. Expected pattern: CVE-YYYY-NNN.',
            show_default=False,
        ),
    ] = None,
    scan_type: Annotated[
        ScanTypeOption,
        typer.Option(
            '--scan-type',
            '-t',
            help='Specify the type of scan you wish to execute.',
            case_sensitive=False,
        ),
    ] = ScanTypeOption.SECRET,
    is_global: Annotated[
        bool, typer.Option('--global', '-g', help='Add an ignore rule to the global CLI config.')
    ] = False,
) -> None:
    """Ignores a specific value, path or rule ID."""
    add_breadcrumb('ignore')

    all_by_values = [by_value, by_sha, by_path, by_rule, by_package, by_cve]
    if all(by is None for by in all_by_values):
        raise click.ClickException('Ignore by type is missing')
    if len([by for by in all_by_values if by is not None]) != 1:
        raise click.ClickException('You must specify only one ignore by type')

    if any(by is not None for by in [by_value, by_sha]) and scan_type != consts.SECRET_SCAN_TYPE:
        raise click.ClickException('This exclude is supported only for Secret scan type')
    if (by_cve or by_package) and scan_type != consts.SCA_SCAN_TYPE:
        raise click.ClickException('This exclude is supported only for SCA scan type')

    # only one of the by values must be set
    # at least one of the by values must be set
    exclusion_type = exclusion_value = None

    if by_value:
        exclusion_type = consts.EXCLUSIONS_BY_VALUE_SECTION_NAME
        exclusion_value = hash_string_to_sha256(by_value)

    if by_sha:
        exclusion_type = consts.EXCLUSIONS_BY_SHA_SECTION_NAME
        exclusion_value = by_sha

    if by_path:
        absolute_path = get_absolute_path(by_path)
        if not is_path_exists(absolute_path):
            raise click.ClickException('The provided path to ignore by does not exist')

        exclusion_type = consts.EXCLUSIONS_BY_PATH_SECTION_NAME
        exclusion_value = get_absolute_path(absolute_path)

    if by_rule:
        exclusion_type = consts.EXCLUSIONS_BY_RULE_SECTION_NAME
        exclusion_value = by_rule

    if by_package:
        if not _is_package_pattern_valid(by_package):
            raise click.ClickException('wrong package pattern. should be name@version.')

        exclusion_type = consts.EXCLUSIONS_BY_PACKAGE_SECTION_NAME
        exclusion_value = by_package

    if by_cve:
        exclusion_type = consts.EXCLUSIONS_BY_CVE_SECTION_NAME
        exclusion_value = by_cve

    if not exclusion_type or not exclusion_value:
        # should never happen
        raise click.ClickException('Invalid ignore by type')

    configuration_scope = 'global' if is_global else 'local'
    logger.debug(
        'Adding ignore rule, %s',
        {
            'configuration_scope': configuration_scope,
            'exclusion_type': exclusion_type,
            'exclusion_value': exclusion_value,
        },
    )
    configuration_manager.add_exclusion(configuration_scope, scan_type, exclusion_type, exclusion_value)
