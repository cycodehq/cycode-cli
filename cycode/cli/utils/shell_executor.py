import subprocess
from typing import List, Optional, Union

import click

from cycode.cyclient import logger

_SUBPROCESS_DEFAULT_TIMEOUT_SEC = 60


def shell(
    command: Union[str, List[str]],
    timeout: int = _SUBPROCESS_DEFAULT_TIMEOUT_SEC,
    working_directory: Optional[str] = None,
) -> Optional[str]:
    logger.debug('Executing shell command: %s', command)

    try:
        result = subprocess.run(  # noqa: S603
            command, cwd=working_directory, timeout=timeout, check=True, capture_output=True
        )

        return result.stdout.decode('UTF-8').strip()
    except subprocess.CalledProcessError as e:
        logger.debug('Error occurred while running shell command', exc_info=e)
    except subprocess.TimeoutExpired as e:
        raise click.Abort(f'Command "{command}" timed out') from e
    except Exception as e:
        raise click.ClickException(f'Unhandled exception: {e}') from e

    return None
