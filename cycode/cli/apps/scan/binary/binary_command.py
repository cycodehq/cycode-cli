from pathlib import Path
from typing import Annotated

import typer

from cycode.cli.apps.scan.binary.identity import (
    assert_monitor_has_an_explicit_identity,
    resolve_platform_identity,
)
from cycode.cli.apps.scan.code_scanner import scan_binary_artifacts
from cycode.cli.logger import logger


def binary_command(
    ctx: typer.Context,
    paths: Annotated[
        list[Path],
        typer.Argument(
            exists=True,
            resolve_path=True,
            help='Paths to the built artifacts to scan',
            show_default=False,
        ),
    ],
) -> None:
    """:package: [bold cyan]Scan built Java artifacts for open-source vulnerabilities.[/]

    Opens a JAR, WAR, EAR or Spring Boot fat JAR, identifies the open-source components inside it, and scans them
    exactly as a source scan would. The artifact never leaves your machine: only the component inventory is
    uploaded.

    Example usage:
    * `cycode scan -t sca binary app.war`: Scan a single deployable.
    * `cycode scan -t sca binary dist/`: Scan every Java archive under a directory.
    * `cycode scan -t sca --max-depth 5 binary app.ear`: Recurse further into nested archives.

    Components are identified from embedded Maven metadata. Anything that cannot be identified is reported in its
    own section rather than guessed at. Relocated and shaded classes are not detected: where source is available,
    a source scan gives a truer dependency graph.

    """
    tuple_paths = tuple(str(path) for path in paths)

    identity = resolve_platform_identity(ctx, tuple_paths)
    if ctx.obj.get('monitor'):
        assert_monitor_has_an_explicit_identity(identity)

    ctx.obj['binary_identity'] = identity

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    logger.debug(
        'Starting binary scan process, %s',
        {'paths': paths, 'identity': identity.value, 'identity_source': identity.source},
    )

    scan_binary_artifacts(ctx, tuple_paths)
