import subprocess
from typing import Optional, Union

import click
import typer

from cycode.logger import get_logger

_SUBPROCESS_DEFAULT_TIMEOUT_SEC = 60


logger = get_logger('SHELL')


def shell(
    command: Union[str, list[str]],
    timeout: int = _SUBPROCESS_DEFAULT_TIMEOUT_SEC,
    working_directory: Optional[str] = None,
    silent_exc_info: bool = False,
) -> Optional[str]:
    logger.debug('Executing shell command: %s', command)

    try:
        result = subprocess.run(  # noqa: S603
            command, cwd=working_directory, timeout=timeout, check=True, capture_output=True
        )
        logger.debug('Shell command executed successfully')

        return result.stdout.decode('UTF-8').strip()
    except subprocess.CalledProcessError as e:
        if not silent_exc_info:
            logger.debug('Error occurred while running shell command', exc_info=e)
    except subprocess.TimeoutExpired as e:
        logger.debug('Command timed out', exc_info=e)
        raise typer.Abort(f'Command "{command}" timed out') from e
    except Exception as e:
        if not silent_exc_info:
            logger.debug('Unhandled exception occurred while running shell command', exc_info=e)

        raise click.ClickException(f'Unhandled exception: {e}') from e

    return None
