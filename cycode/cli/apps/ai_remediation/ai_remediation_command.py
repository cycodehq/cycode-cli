from typing import Annotated
from uuid import UUID

import typer

from cycode.cli.apps.ai_remediation.apply_fix import apply_fix
from cycode.cli.apps.ai_remediation.print_remediation import print_remediation
from cycode.cli.exceptions.handle_ai_remediation_errors import handle_ai_remediation_exception
from cycode.cli.utils.get_api_client import get_scan_cycode_client


def ai_remediation_command(
    ctx: typer.Context,
    detection_id: Annotated[UUID, typer.Argument(help='Detection ID to get remediation for', show_default=False)],
    fix: Annotated[
        bool, typer.Option('--fix', help='Apply fixes to resolve violations. Note: fix could be not available.')
    ] = False,
) -> None:
    """:robot: [bold cyan]Get AI-powered remediation for security issues.[/]

    This command provides AI-generated remediation guidance for detected security issues.

    Example usage:
    * `cycode ai-remediation <detection_id>`: View remediation guidance
    * `cycode ai-remediation <detection_id> --fix`: Apply suggested fixes
    """
    client = get_scan_cycode_client(ctx)

    try:
        remediation_markdown = client.get_ai_remediation(detection_id)
        fix_diff = client.get_ai_remediation(detection_id, fix=True)
        is_fix_available = bool(fix_diff)  # exclude empty string, None, etc.

        if fix:
            apply_fix(ctx, fix_diff, is_fix_available)
        else:
            print_remediation(ctx, remediation_markdown, is_fix_available)
    except Exception as err:
        handle_ai_remediation_exception(ctx, err)
