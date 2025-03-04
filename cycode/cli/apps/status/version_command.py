import typer

from cycode.cli.apps.status.status_command import status_command


def version_command(ctx: typer.Context) -> None:
    typer.echo(
        typer.style(
            text='The "version" command is deprecated. Please use the "status" command instead.',
            fg=typer.colors.YELLOW,
            bold=True,
        ),
        color=ctx.color,
    )
    status_command(ctx)
