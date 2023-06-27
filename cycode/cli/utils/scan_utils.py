import click


def is_scan_failed(context: click.Context) -> bool:
    did_fail = context.obj.get('did_fail')

    # TODO REWORK we have many issue_detected in batches.
    issue_detected = context.obj.get('issue_detected')

    return did_fail or issue_detected
