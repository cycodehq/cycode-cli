import logging
import sys
from typing import ClassVar, NamedTuple, Optional, Union

import click
import typer
from rich.logging import RichHandler

from cycode.cli import consts
from cycode.cli.console import console_err
from cycode.config import get_val_as_string


def _set_io_encodings() -> None:
    # set io encoding (for Windows)
    sys.stdout.reconfigure(encoding='UTF-8')
    sys.stderr.reconfigure(encoding='UTF-8')


_set_io_encodings()

_RICH_LOGGING_HANDLER = RichHandler(console=console_err, rich_tracebacks=True, tracebacks_suppress=[click, typer])

logging.basicConfig(
    level=logging.INFO,
    format='[%(name)s] %(message)s',
    handlers=[_RICH_LOGGING_HANDLER],
)

logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('schedule').setLevel(logging.WARNING)
logging.getLogger('kubernetes').setLevel(logging.WARNING)
logging.getLogger('binaryornot').setLevel(logging.WARNING)
logging.getLogger('chardet').setLevel(logging.WARNING)
logging.getLogger('git.cmd').setLevel(logging.WARNING)
logging.getLogger('git.util').setLevel(logging.WARNING)


class CreatedLogger(NamedTuple):
    logger: logging.Logger
    control_level_in_runtime: bool


class LoggersManager:
    loggers: ClassVar[set[CreatedLogger]] = set()
    global_logging_level: Optional[int] = None


def get_logger_level() -> Optional[Union[int, str]]:
    if LoggersManager.global_logging_level is not None:
        return LoggersManager.global_logging_level

    config_level = get_val_as_string(consts.LOGGING_LEVEL_ENV_VAR_NAME)
    return logging.getLevelName(config_level)


def get_logger(logger_name: Optional[str] = None, control_level_in_runtime: bool = True) -> logging.Logger:
    new_logger = logging.getLogger(logger_name)
    new_logger.setLevel(get_logger_level())

    LoggersManager.loggers.add(CreatedLogger(logger=new_logger, control_level_in_runtime=control_level_in_runtime))

    return new_logger


def set_logging_level(level: int) -> None:
    LoggersManager.global_logging_level = level

    for created_logger in LoggersManager.loggers:
        if created_logger.control_level_in_runtime:
            created_logger.logger.setLevel(level)
