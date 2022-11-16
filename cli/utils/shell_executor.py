from typing import List, Optional
import subprocess
import click
from cyclient import logger

TIMEOUT = 60


def shell(command: List[str], timeout: int = TIMEOUT) -> Optional[str]:
    click.echo(f"executing shell command: {' '.join(map(str, command))}")
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return result.stdout.decode("utf-8").rstrip()
    except subprocess.CalledProcessError as e:
        logger.debug('Failed to run shell command. %s', {'command': command, 'exception': str(e)})
        pass
    except subprocess.TimeoutExpired:
        raise click.Abort(f'Command {" ".join(map(str, command))} timed out')
    except Exception as exc:
        raise click.ClickException(f"Unhandled exception: {str(exc)}")

    return None
