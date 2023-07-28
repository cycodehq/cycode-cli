import os.path
import re
from typing import Optional

import click

from cycode.cli import consts
from cycode.cli.config import config, configuration_manager
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.utils.path_utils import get_absolute_path
from cycode.cli.utils.string_utils import hash_string_to_sha256, obfuscate_text
from cycode.cyclient import logger

CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE = 'Successfully configured CLI credentials!'
CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE = (
    'Note that the credentials that already exist in environment'
    ' variables (CYCODE_CLIENT_ID and CYCODE_CLIENT_SECRET) take'
    ' precedent over these credentials; either update or remove '
    'the environment variables.'
)
credentials_manager = CredentialsManager()


@click.command(
    short_help='Initial command to authenticate your CLI client with Cycode using a client ID and client secret.'
)
def set_credentials() -> None:
    """Authenticates your CLI client with Cycode manually by using a client ID and client secret."""
    click.echo(f'Update credentials in file ({credentials_manager.get_filename()})')
    current_client_id, current_client_secret = credentials_manager.get_credentials_from_file()
    client_id = _get_client_id_input(current_client_id)
    client_secret = _get_client_secret_input(current_client_secret)

    if not _should_update_credentials(current_client_id, current_client_secret, client_id, client_secret):
        return

    credentials_manager.update_credentials_file(client_id, client_secret)
    click.echo(_get_credentials_update_result_message())


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
def add_exclusions(
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


def _get_client_id_input(current_client_id: str) -> str:
    new_client_id = click.prompt(
        f'cycode client id [{_obfuscate_credential(current_client_id)}]', default='', show_default=False
    )

    return new_client_id if new_client_id else current_client_id


def _get_client_secret_input(current_client_secret: str) -> str:
    new_client_secret = click.prompt(
        f'cycode client secret [{_obfuscate_credential(current_client_secret)}]', default='', show_default=False
    )
    return new_client_secret if new_client_secret else current_client_secret


def _get_credentials_update_result_message() -> str:
    if not _are_credentials_exist_in_environment_variables():
        return CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE

    return CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE + ' ' + CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE


def _are_credentials_exist_in_environment_variables() -> bool:
    client_id, client_secret = credentials_manager.get_credentials_from_environment_variables()
    return client_id is not None or client_secret is not None


def _should_update_credentials(
    current_client_id: str, current_client_secret: str, new_client_id: str, new_client_secret: str
) -> bool:
    return current_client_id != new_client_id or current_client_secret != new_client_secret


def _obfuscate_credential(credential: Optional[str]) -> str:
    return '' if not credential else obfuscate_text(credential)


def _is_path_to_ignore_exists(path: str) -> bool:
    return os.path.exists(path)


def _is_package_pattern_valid(package: str) -> bool:
    return re.search('^[^@]+@[^@]+$', package) is not None
