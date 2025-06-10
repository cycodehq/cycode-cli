import os
from typing import Optional

import typer

from cycode.cli.apps.scan.remote_url_resolver import try_get_any_remote_url
from cycode.cli.utils.scan_utils import generate_unique_scan_id
from cycode.logger import get_logger

logger = get_logger('Scan Parameters')


def _get_default_scan_parameters(ctx: typer.Context) -> dict:
    return {
        'monitor': ctx.obj.get('monitor'),
        'report': ctx.obj.get('report'),
        'package_vulnerabilities': ctx.obj.get('package-vulnerabilities'),
        'license_compliance': ctx.obj.get('license-compliance'),
        'command_type': ctx.info_name.replace('-', '_'),  # save backward compatibility
        'aggregation_id': str(generate_unique_scan_id()),
    }


def get_scan_parameters(ctx: typer.Context, paths: Optional[tuple[str, ...]] = None) -> dict:
    scan_parameters = _get_default_scan_parameters(ctx)

    if not paths:
        return scan_parameters

    scan_parameters['paths'] = paths

    if len(paths) != 1:
        logger.debug('Multiple paths provided, going to ignore remote url')
        return scan_parameters

    if not os.path.isdir(paths[0]):
        logger.debug('Path is not a directory, going to ignore remote url')
        return scan_parameters

    remote_url = try_get_any_remote_url(paths[0])
    if remote_url:
        # TODO(MarshalX): remove hardcode in context
        ctx.obj['remote_url'] = remote_url
        scan_parameters['remote_url'] = remote_url

    return scan_parameters
