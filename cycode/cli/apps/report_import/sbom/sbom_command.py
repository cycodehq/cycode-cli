from pathlib import Path
from typing import Annotated, Optional

import typer

from cycode.cli.cli_types import BusinessImpactOption
from cycode.cli.exceptions.handle_report_sbom_errors import handle_report_exception
from cycode.cli.utils.get_api_client import get_import_sbom_cycode_client
from cycode.cli.utils.sentry import add_breadcrumb
from cycode.cyclient.import_sbom_client import ImportSbomParameters


def sbom_command(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(
            exists=True, resolve_path=True, dir_okay=False, readable=True, help='Path to SBOM file.', show_default=False
        ),
    ],
    sbom_name: Annotated[
        str, typer.Option('--name', '-n', help='SBOM Name.', case_sensitive=False, show_default=False)
    ],
    vendor: Annotated[
        str, typer.Option('--vendor', '-v', help='Vendor Name.', case_sensitive=False, show_default=False)
    ],
    labels: Annotated[
        Optional[list[str]],
        typer.Option(
            '--label', '-l', help='Label, can be specified multiple times.', case_sensitive=False, show_default=False
        ),
    ] = None,
    owners: Annotated[
        Optional[list[str]],
        typer.Option(
            '--owner',
            '-o',
            help='Email address of a user in Cycode platform, can be specified multiple times.',
            case_sensitive=True,
            show_default=False,
        ),
    ] = None,
    business_impact: Annotated[
        BusinessImpactOption,
        typer.Option(
            '--business-impact',
            '-b',
            help='Business Impact.',
            case_sensitive=True,
            show_default=True,
        ),
    ] = BusinessImpactOption.MEDIUM,
) -> None:
    """Import SBOM."""
    add_breadcrumb('sbom')

    client = get_import_sbom_cycode_client(ctx)

    import_parameters = ImportSbomParameters(
        Name=sbom_name,
        Vendor=vendor,
        BusinessImpact=business_impact,
        Labels=labels,
        Owners=owners,
    )

    try:
        if not path.exists():
            from errno import ENOENT
            from os import strerror

            raise FileNotFoundError(ENOENT, strerror(ENOENT), path.absolute())

        client.request_sbom_import_execution(import_parameters, path)
    except Exception as e:
        handle_report_exception(ctx, e)
