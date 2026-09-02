"""Self-detach support for report-mode scans.

In report mode nobody consumes the hook verdict, so the scan respawns itself
detached and the parent exits immediately — the IDE is released after roughly
CLI startup instead of waiting for a full scan. The child's handles are set at
process-creation time (stdout/stderr to devnull, payload piped to stdin), so it
never inherits the IDE's pipes: a backgrounded child that shares the hook's
stdout keeps EOF-waiting runners blocked for the scan's full duration.
"""

import os
import subprocess
import sys

from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

DETACHED_ENV_VAR = '_CYCODE_DETACHED'

# Numeric fallbacks let non-Windows platforms (tests included) build the same flags.
_WINDOWS_CREATIONFLAGS = (
    getattr(subprocess, 'DETACHED_PROCESS', 0x00000008)
    | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x00000200)
    | getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
)


def is_detached_child() -> bool:
    """Whether this process is the respawned detached child."""
    return os.environ.get(DETACHED_ENV_VAR) == '1'


def build_respawn_command() -> list[str]:
    """The command that re-runs the current invocation.

    Under PyInstaller sys.executable is the CLI binary itself; otherwise it is
    the Python interpreter and argv[0] is the console script to re-run.
    """
    if getattr(sys, 'frozen', False):
        return [sys.executable, *sys.argv[1:]]
    return [sys.executable, *sys.argv]


def respawn_detached(stdin_payload: str) -> bool:
    """Respawn the current command detached, feeding it ``stdin_payload``.

    Returns False when the respawn failed, so the caller can fall back to the
    synchronous path instead of dropping the event.
    """
    try:
        detach_kwargs = (
            {'creationflags': _WINDOWS_CREATIONFLAGS} if sys.platform == 'win32' else {'start_new_session': True}
        )
        process = subprocess.Popen(  # noqa: S603
            build_respawn_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, DETACHED_ENV_VAR: '1'},
            **detach_kwargs,
        )
        # Hand over the payload and close, then return without waiting - the
        # whole point is that the parent exits while the child scans.
        process.stdin.write(stdin_payload.encode('utf-8'))
        process.stdin.close()
        logger.debug('Respawned detached scan', extra={'child_pid': process.pid})
        return True
    except Exception as e:
        logger.debug('Failed to respawn detached, falling back to synchronous scan', exc_info=e)
        return False
