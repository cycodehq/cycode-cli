"""Cycode platform API CLI commands.

Dynamically builds CLI command groups from the Cycode API v4 OpenAPI spec.
The spec is fetched lazily — only when the user invokes `cycode platform ...` —
and cached locally for 24 hours.
"""

from typing import Any, Optional

import click

from cycode.logger import get_logger

logger = get_logger('Platform')

_PLATFORM_HELP = (
    '[BETA] Access the Cycode platform.\n\n'
    'Commands are generated dynamically from the Cycode API spec and may change '
    'between releases. The spec is fetched on first use and cached for 24 hours.'
)


class PlatformGroup(click.Group):
    """Lazy-loading Click group for `cycode platform` subcommands.

    The OpenAPI spec is only fetched when the user actually invokes
    `cycode platform ...` (or asks for its help). Unrelated commands like
    `cycode scan` or `cycode status` never trigger a spec fetch.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._loaded: bool = False

    def _ensure_loaded(self, ctx: Optional[click.Context]) -> None:
        if self._loaded:
            return
        self._loaded = True  # set first to avoid re-entrancy on errors

        client_id = client_secret = None
        if ctx is not None:
            root = ctx.find_root()
            if root.obj:
                client_id = root.obj.get('client_id')
                client_secret = root.obj.get('client_secret')

        try:
            from cycode.cli.apps.api.api_command import build_api_command_groups

            for sub_group, name in build_api_command_groups(client_id, client_secret):
                if name not in self.commands:
                    self.add_command(sub_group, name)
        except Exception as e:
            logger.debug('Could not load platform commands: %s', e)
            # Surface the error to the user only when they're inside `platform`
            click.echo(f'Error loading Cycode platform commands: {e}', err=True)

    def list_commands(self, ctx: click.Context) -> list[str]:
        self._ensure_loaded(ctx)
        return super().list_commands(ctx)

    def get_command(self, ctx: click.Context, cmd_name: str) -> Optional[click.Command]:
        self._ensure_loaded(ctx)
        return super().get_command(ctx, cmd_name)


def get_platform_group() -> click.Group:
    """Return the top-level `platform` Click group (lazy-loading)."""
    return PlatformGroup(name='platform', help=_PLATFORM_HELP, no_args_is_help=True)
