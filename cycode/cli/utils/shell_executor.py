import subprocess
from typing import List, Optional, Union

import click

from cycode.cyclient import logger

_SUBPROCESS_DEFAULT_TIMEOUT_SEC = 60


def shell(
    command: Union[str, List[str]], timeout: int = _SUBPROCESS_DEFAULT_TIMEOUT_SEC, execute_in_shell: bool = False
) -> Optional[str]:
    logger.debug(f'Executing shell command: {command}')

    try:
        result = subprocess.run(
            command,
            timeout=timeout,
            shell=execute_in_shell,  # noqa: S603
            check=True,
            capture_output=True,
        )

        return result.stdout.decode('UTF-8').strip()
    except subprocess.CalledProcessError as e:
        logger.debug(f'Error occurred while running shell command. Exception: {e.stderr}')
    except subprocess.TimeoutExpired as e:
        raise click.Abort(f'Command "{command}" timed out') from e
    except Exception as e:
        raise click.ClickException(f'Unhandled exception: {e}') from e

    return None
