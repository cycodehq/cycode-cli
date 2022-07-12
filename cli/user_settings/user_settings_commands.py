import os.path
import click
from typing import Optional
from cli.utils.string_utils import obfuscate_text, convert_string_to_sha256
from cli.utils.path_utils import get_absolute_path
from cli.user_settings.credentials_manager import CredentialsManager
from cli.config import configuration_manager, config
from cli.consts import SECRET_SCAN_TYPE, EXCLUSIONS_BY_VALUE_SECTION_NAME, EXCLUSIONS_BY_SHA_SECTION_NAME, \
    EXCLUSIONS_BY_PATH_SECTION_NAME, EXCLUSIONS_BY_RULE_SECTION_NAME
from cyclient import logger

CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE = 'Successfully configured CLI credentials!'
CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE = 'Note that the credentials that already exist in environment' \
                                                       ' variables (CYCODE_CLIENT_ID and CYCODE_CLIENT_SECRET) take' \
                                                       ' precedent over these credentials; either update or remove ' \
                                                       'the environment variables.'
credentials_manager = CredentialsManager()


@click.command()
def set_credentials():
    """ Initial command to authenticate your CLI client with Cycode using client ID and client secret """
    click.echo(f'Update credentials in file ({credentials_manager.get_filename()})')
    current_client_id, current_client_secret = credentials_manager.get_credentials_from_file()
    client_id = _get_client_id_input(current_client_id)
    client_secret = _get_client_secret_input(current_client_secret)

    if not _should_update_credentials(current_client_id, current_client_secret, client_id, client_secret):
        return

    credentials_manager.update_credentials_file(client_id, client_secret)
    click.echo(_get_credentials_update_result_message())


@click.command()
@click.option("--by-value", type=click.STRING, required=False,
              help="Ignore a specific value while scanning for secrets")
@click.option("--by-sha", type=click.STRING, required=False,
              help='Ignore a specific SHA512 representation of a string while scanning for secrets')
@click.option("--by-path", type=click.STRING, required=False,
              help='Avoid scanning a specific path. Need to specify scan type ')
@click.option("--by-rule", type=click.STRING, required=False,
              help='Ignore scanning a specific secret rule ID/IaC rule ID. Need to specify scan type.')
@click.option('--scan-type', '-t', default='secret',
              help="""
              \b
              Specify the scan you wish to execute (secrets/iac), 
              the default is secrets
              """,
              type=click.Choice(config['scans']['supported_scans']), required=False)
@click.option('--global', '-g', 'is_global', is_flag=True, default=False, required=False,
              help='Add an ignore rule and update it in the global .cycode config file')
def add_exclusions(by_value: str, by_sha: str, by_path: str, by_rule: str, scan_type: str,
                   is_global: bool):
    """ Ignore a specific value, path or rule ID """
    if not by_value and not by_sha and not by_path and not by_rule:
        raise click.ClickException("ignore by type is missing")

    if by_value is not None:
        if scan_type != SECRET_SCAN_TYPE:
            raise click.ClickException("exclude by value is supported only for secret scan type")
        exclusion_type = EXCLUSIONS_BY_VALUE_SECTION_NAME
        exclusion_value = convert_string_to_sha256(by_value)
    elif by_sha is not None:
        if scan_type != SECRET_SCAN_TYPE:
            raise click.ClickException("exclude by sha is supported only for secret scan type")
        exclusion_type = EXCLUSIONS_BY_SHA_SECTION_NAME
        exclusion_value = by_sha
    elif by_path is not None:
        absolute_path = get_absolute_path(by_path)
        if not _is_path_to_ignore_exists(absolute_path):
            raise click.ClickException("the provided path to ignore by is not exist")
        exclusion_type = EXCLUSIONS_BY_PATH_SECTION_NAME
        exclusion_value = get_absolute_path(absolute_path)
    else:
        exclusion_type = EXCLUSIONS_BY_RULE_SECTION_NAME
        exclusion_value = by_rule

    configuration_scope = 'global' if is_global else 'local'
    logger.debug('Adding ignore rule, %s',
                 {'configuration_scope': configuration_scope, 'exclusion_type': exclusion_type,
                  'exclusion_value': exclusion_value})
    configuration_manager.add_exclusion(configuration_scope, scan_type, exclusion_type, exclusion_value)


def _get_client_id_input(current_client_id: str) -> str:
    new_client_id = click.prompt(f'cycode client id [{_obfuscate_credential(current_client_id)}]',
                                 default='',
                                 show_default=False)

    return current_client_id if not new_client_id else new_client_id


def _get_client_secret_input(current_client_secret: str) -> str:
    new_client_secret = click.prompt(f'cycode client secret [{_obfuscate_credential(current_client_secret)}]',
                                     default='',
                                     show_default=False)
    return current_client_secret if not new_client_secret else new_client_secret


def _get_credentials_update_result_message():
    if not _are_credentials_exist_in_environment_variables():
        return CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE

    return CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE + ' ' + CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE


def _are_credentials_exist_in_environment_variables():
    client_id, client_secret = credentials_manager.get_credentials_from_environment_variables()
    return client_id is not None or client_secret is not None


def _should_update_credentials(current_client_id: str, current_client_secret: str, new_client_id: str,
                               new_client_secret: str) -> bool:
    return current_client_id != new_client_id or current_client_secret != new_client_secret


def _obfuscate_credential(credential: Optional[str]) -> str:
    return '' if not credential else obfuscate_text(credential)


def _is_path_to_ignore_exists(path: str) -> bool:
    return os.path.exists(path)
