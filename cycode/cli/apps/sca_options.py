from pathlib import Path
from typing import Annotated, Optional

import typer

_SCA_RICH_HELP_PANEL = 'SCA options'

NoRestoreOption = Annotated[
    bool,
    typer.Option(
        '--no-restore',
        help='When specified, Cycode will not run restore command. Will scan direct dependencies [b]only[/]!',
        rich_help_panel=_SCA_RICH_HELP_PANEL,
    ),
]

GradleAllSubProjectsOption = Annotated[
    bool,
    typer.Option(
        '--gradle-all-sub-projects',
        help='When specified, Cycode will run gradle restore command for all sub projects. '
        'Should run from root project directory [b]only[/]!',
        rich_help_panel=_SCA_RICH_HELP_PANEL,
    ),
]

MavenSettingsFileOption = Annotated[
    Optional[Path],
    typer.Option(
        '--maven-settings-file',
        show_default=False,
        help='When specified, Cycode will use this settings.xml file when building the maven dependency tree.',
        dir_okay=False,
        rich_help_panel=_SCA_RICH_HELP_PANEL,
    ),
]


def apply_sca_restore_options_to_context(
    ctx: typer.Context,
    no_restore: bool,
    gradle_all_sub_projects: bool,
    maven_settings_file: Optional[Path],
) -> None:
    ctx.obj['no_restore'] = no_restore
    ctx.obj['gradle_all_sub_projects'] = gradle_all_sub_projects
    ctx.obj['maven_settings_file'] = maven_settings_file
