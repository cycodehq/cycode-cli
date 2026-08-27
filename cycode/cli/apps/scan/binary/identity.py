"""What the platform files a binary scan under.

Identity lives with the command rather than with the collector: it is a question about how results are recorded,
not about how an archive is read, and keeping it here leaves the collector free of any dependency on the scan app.
"""

import os
from dataclasses import dataclass

import typer

from cycode.cli.apps.scan.remote_url_resolver import get_remote_url_scan_parameter
from cycode.cli.files_collector.binary.collector import find_supported_artifacts

IDENTITY_FROM_PROJECT_NAME = 'project-name'
IDENTITY_FROM_GIT_REMOTE = 'git-remote'
IDENTITY_FROM_FILENAME = 'filename'


@dataclass(frozen=True)
class PlatformIdentity:
    """What the platform will file these results under, and where that came from."""

    value: str
    source: str

    @property
    def is_explicit(self) -> bool:
        """True when a human or a repository named this project, rather than it being taken off a filename."""
        return self.source in (IDENTITY_FROM_PROJECT_NAME, IDENTITY_FROM_GIT_REMOTE)


def resolve_platform_identity(ctx: typer.Context, paths: tuple[str, ...]) -> PlatformIdentity:
    """Inside a repository, results attach to that repository exactly as a path scan does.

    Detached from one, the artifact filename is the identity, which is fine for a one-off assessment and is
    explicitly not fine for monitoring.
    """
    project_name = ctx.obj.get('project_name')
    if project_name:
        return PlatformIdentity(value=project_name, source=IDENTITY_FROM_PROJECT_NAME)

    remote_url = get_remote_url_scan_parameter(paths)
    if remote_url:
        return PlatformIdentity(value=remote_url, source=IDENTITY_FROM_GIT_REMOTE)

    artifacts = find_supported_artifacts(paths)
    filename = os.path.basename(artifacts[0]) if artifacts else os.path.basename(paths[0])
    return PlatformIdentity(value=filename, source=IDENTITY_FROM_FILENAME)


def assert_monitor_has_an_explicit_identity(identity: PlatformIdentity) -> None:
    """Refuse --monitor on a bare filename identity.

    Monitoring keyed on `app.jar` would merge unrelated teams into one project and quietly corrupt the trend data,
    which is worse than refusing: the damage is invisible until someone acts on the numbers.
    """
    if identity.is_explicit:
        return

    raise typer.BadParameter(
        f'--monitor needs an explicit project identity, but the only identity available is the artifact filename '
        f'({identity.value!r}). Run from inside the Git repository this artifact was built from, or pass '
        f'--project-name to name the project yourself.',
        param_hint='--monitor',
    )
