import subprocess
import time
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
        start = time.monotonic()
        result = subprocess.run(  # noqa: S603
            command, cwd=working_directory, timeout=timeout, check=True, capture_output=True
        )
        duration_sec = round(time.monotonic() - start, 2)
        stdout = result.stdout.decode('UTF-8').strip()
        stderr = result.stderr.decode('UTF-8').strip()

        logger.debug(
            'Shell command executed successfully, %s',
            {'duration_sec': duration_sec, 'stdout': stdout if stdout else '', 'stderr': stderr if stderr else ''},
        )

        return stdout
    except subprocess.CalledProcessError as e:
        if not silent_exc_info:
            logger.debug('Error occurred while running shell command', exc_info=e)
            if e.stdout:
                logger.debug('Shell command stdout: %s', e.stdout.decode('UTF-8').strip())
            if e.stderr:
                logger.debug('Shell command stderr: %s', e.stderr.decode('UTF-8').strip())
    except subprocess.TimeoutExpired as e:
        logger.debug('Command timed out', exc_info=e)
        raise typer.Abort(f'Command "{command}" timed out') from e
    except Exception as e:
        if not silent_exc_info:
            logger.debug('Unhandled exception occurred while running shell command', exc_info=e)

        raise click.ClickException(f'Unhandled exception: {e}') from e

    return None
