import os
from typing import Annotated, Optional

import click
import typer

from cycode.cli import consts
from cycode.cli.apps.scan.code_scanner import (
    enable_verbose_mode,
    is_verbose_mode_requested_in_pre_receive_scan,
    parse_pre_receive_input,
    perform_post_pre_receive_scan_actions,
    scan_commit_range,
    should_skip_pre_receive_scan,
)
from cycode.cli.config import configuration_manager
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.files_collector.repository_documents import (
    calculate_pre_receive_commit_range,
)
from cycode.cli.logger import logger
from cycode.cli.utils.sentry import add_breadcrumb
from cycode.cli.utils.task_timer import TimeoutAfter


def pre_receive_command(
    ctx: typer.Context,
    _: Annotated[Optional[list[str]], typer.Argument(help='Ignored arguments', hidden=True)] = None,
) -> None:
    try:
        add_breadcrumb('pre_receive')

        scan_type = ctx.obj['scan_type']
        if scan_type != consts.SECRET_SCAN_TYPE:
            raise click.ClickException(f'Commit range scanning for {scan_type.upper()} is not supported')

        if should_skip_pre_receive_scan():
            logger.info(
                'A scan has been skipped as per your request. '
                'Please note that this may leave your system vulnerable to secrets that have not been detected.'
            )
            return

        if is_verbose_mode_requested_in_pre_receive_scan():
            enable_verbose_mode(ctx)
            logger.debug('Verbose mode enabled: all log levels will be displayed.')

        command_scan_type = ctx.info_name
        timeout = configuration_manager.get_pre_receive_command_timeout(command_scan_type)
        with TimeoutAfter(timeout):
            if scan_type not in consts.COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES:
                raise click.ClickException(f'Commit range scanning for {scan_type.upper()} is not supported')

            branch_update_details = parse_pre_receive_input()
            commit_range = calculate_pre_receive_commit_range(branch_update_details)
            if not commit_range:
                logger.info(
                    'No new commits found for pushed branch, %s',
                    {'branch_update_details': branch_update_details},
                )
                return

            max_commits_to_scan = configuration_manager.get_pre_receive_max_commits_to_scan_count(command_scan_type)
            scan_commit_range(ctx, os.getcwd(), commit_range, max_commits_count=max_commits_to_scan)
            perform_post_pre_receive_scan_actions(ctx)
    except Exception as e:
        handle_scan_exception(ctx, e)
