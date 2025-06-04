import logging
import os
from typing import Annotated, Optional

import typer

from cycode.cli import consts
from cycode.cli.apps.scan.commit_range_scanner import (
    is_verbose_mode_requested_in_pre_receive_scan,
    scan_commit_range,
    should_skip_pre_receive_scan,
)
from cycode.cli.config import configuration_manager
from cycode.cli.console import console
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.files_collector.commit_range_documents import (
    calculate_pre_receive_commit_range,
    parse_pre_receive_input,
)
from cycode.cli.logger import logger
from cycode.cli.utils import scan_utils
from cycode.cli.utils.sentry import add_breadcrumb
from cycode.cli.utils.task_timer import TimeoutAfter
from cycode.logger import set_logging_level


def pre_receive_command(
    ctx: typer.Context,
    _: Annotated[Optional[list[str]], typer.Argument(help='Ignored arguments', hidden=True)] = None,
) -> None:
    try:
        add_breadcrumb('pre_receive')

        if should_skip_pre_receive_scan():
            logger.info(
                'A scan has been skipped as per your request. '
                'Please note that this may leave your system vulnerable to secrets that have not been detected.'
            )
            return

        if is_verbose_mode_requested_in_pre_receive_scan():
            ctx.obj['verbose'] = True
            set_logging_level(logging.DEBUG)
            logger.debug('Verbose mode enabled: all log levels will be displayed.')

        command_scan_type = ctx.info_name
        timeout = configuration_manager.get_pre_receive_command_timeout(command_scan_type)
        with TimeoutAfter(timeout):
            branch_update_details = parse_pre_receive_input()
            commit_range = calculate_pre_receive_commit_range(branch_update_details)
            if not commit_range:
                logger.info(
                    'No new commits found for pushed branch, %s',
                    {'branch_update_details': branch_update_details},
                )
                return

            scan_commit_range(
                ctx=ctx,
                repo_path=os.getcwd(),
                commit_range=commit_range,
                max_commits_count=configuration_manager.get_pre_receive_max_commits_to_scan_count(command_scan_type),
            )

            if scan_utils.is_scan_failed(ctx):
                console.print(consts.PRE_RECEIVE_REMEDIATION_MESSAGE)
    except Exception as e:
        handle_scan_exception(ctx, e)
