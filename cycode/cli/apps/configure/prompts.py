from typing import Optional

import typer

from cycode.cli import consts
from cycode.cli.utils.string_utils import obfuscate_text


def get_client_id_input(current_client_id: Optional[str]) -> Optional[str]:
    prompt_text = 'Cycode Client ID'

    prompt_suffix = ' []: '
    if current_client_id:
        prompt_suffix = f' [{obfuscate_text(current_client_id)}]: '

    new_client_id = typer.prompt(text=prompt_text, prompt_suffix=prompt_suffix, default='', show_default=False)
    return new_client_id or current_client_id


def get_client_secret_input(current_client_secret: Optional[str]) -> Optional[str]:
    prompt_text = 'Cycode Client Secret'

    prompt_suffix = ' []: '
    if current_client_secret:
        prompt_suffix = f' [{obfuscate_text(current_client_secret)}]: '

    new_client_secret = typer.prompt(text=prompt_text, prompt_suffix=prompt_suffix, default='', show_default=False)
    return new_client_secret or current_client_secret


def get_app_url_input(current_app_url: Optional[str]) -> str:
    prompt_text = 'Cycode APP URL'

    default = consts.DEFAULT_CYCODE_APP_URL
    if current_app_url:
        default = current_app_url

    return typer.prompt(text=prompt_text, default=default, type=str)


def get_api_url_input(current_api_url: Optional[str]) -> str:
    prompt_text = 'Cycode API URL'

    default = consts.DEFAULT_CYCODE_API_URL
    if current_api_url:
        default = current_api_url

    return typer.prompt(text=prompt_text, default=default, type=str)
