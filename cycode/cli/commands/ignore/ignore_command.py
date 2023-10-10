import os
import re

import click

from cycode.cli import consts
from cycode.cli.config import config, configuration_manager
from cycode.cli.utils.path_utils import get_absolute_path
from cycode.cli.utils.string_utils import hash_string_to_sha256
from cycode.cyclient import logger


def _is_path_to_ignore_exists(path: str) -> bool:
    return os.path.exists(path)


def _is_package_pattern_valid(package: str) -> bool:
    return re.search('^[^@]+@[^@]+$', package) is not None


@click.command(short_help='Ignores a specific value, path or rule ID.')
@click.option(
    '--by-value', type=click.STRING, required=False, help='Ignore a specific value while scanning for Secrets.'
)
@click.option(
    '--by-sha',
    type=click.STRING,
    required=False,
    help='Ignore a specific SHA512 representation of a string while scanning for Secrets.',
)
@click.option(
    '--by-path',
    type=click.STRING,
    required=False,
    help='Avoid scanning a specific path. You`ll need to specify the scan type.',
)
@click.option(
    '--by-rule',
    type=click.STRING,
    required=False,
    help='Ignore scanning a specific secret rule ID or IaC rule ID. You`ll to specify the scan type.',
)
@click.option(
    '--by-package',
    type=click.STRING,
    required=False,
    help='Ignore scanning a specific package version while running an SCA scan. Expected pattern: name@version.',
)
@click.option(
    '--scan-type',
    '-t',
    default='secret',
    help='Specify the type of scan you wish to execute (the default is Secrets).',
    type=click.Choice(config['scans']['supported_scans']),
    required=False,
)
@click.option(
    '--global',
    '-g',
    'is_global',
    is_flag=True,
    default=False,
    required=False,
    help='Add an ignore rule to the global CLI config.',
)
def ignore_command(
    by_value: str, by_sha: str, by_path: str, by_rule: str, by_package: str, scan_type: str, is_global: bool
) -> None:
    """Ignores a specific value, path or rule ID."""
    if not by_value and not by_sha and not by_path and not by_rule and not by_package:
        raise click.ClickException('ignore by type is missing')

    if any(by is not None for by in [by_value, by_sha]) and scan_type != consts.SECRET_SCAN_TYPE:
        raise click.ClickException('this exclude is supported only for secret scan type')

    if by_value is not None:
        exclusion_type = consts.EXCLUSIONS_BY_VALUE_SECTION_NAME
        exclusion_value = hash_string_to_sha256(by_value)
    elif by_sha is not None:
        exclusion_type = consts.EXCLUSIONS_BY_SHA_SECTION_NAME
        exclusion_value = by_sha
    elif by_path is not None:
        absolute_path = get_absolute_path(by_path)
        if not _is_path_to_ignore_exists(absolute_path):
            raise click.ClickException('the provided path to ignore by is not exist')
        exclusion_type = consts.EXCLUSIONS_BY_PATH_SECTION_NAME
        exclusion_value = get_absolute_path(absolute_path)
    elif by_package is not None:
        if scan_type != consts.SCA_SCAN_TYPE:
            raise click.ClickException('exclude by package is supported only for sca scan type')
        if not _is_package_pattern_valid(by_package):
            raise click.ClickException('wrong package pattern. should be name@version.')
        exclusion_type = consts.EXCLUSIONS_BY_PACKAGE_SECTION_NAME
        exclusion_value = by_package
    else:
        exclusion_type = consts.EXCLUSIONS_BY_RULE_SECTION_NAME
        exclusion_value = by_rule

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
