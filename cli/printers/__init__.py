import json

import click

from cli.models import CliError, CliResult

from cli.printers.json_printer import JsonPrinter
from cli.printers.text_printer import TextPrinter
from cli.printers.results_printer import ResultsPrinter


__all__ = [
    'JsonPrinter',
    'TextPrinter',
    'ResultsPrinter',
    'print_cli_error',
    'print_cli_result',
]


def _get_data_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False)     # ensure_ascii is disabled for symbols like "`". Eg: `cycode scan`


def print_cli_error(output: str, error: CliError) -> None:
    if output == 'text':
        click.secho(error.message, fg='red', nl=False)
        return

    click.echo(_get_data_json({'error': error.code, 'message': error.message}))


def print_cli_result(output: str, result: CliResult) -> None:
    color = 'red'
    if result.success:
        color = 'green'

    if output == 'text':
        click.secho(result.message, fg=color)
        return

    click.echo(_get_data_json({'result': result.success, 'message': result.message}))
