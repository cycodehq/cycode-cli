import click


def set_issue_detected(context: click.Context, issue_detected: bool) -> None:
    context.obj['issue_detected'] = issue_detected


def is_scan_failed(context: click.Context) -> bool:
    did_fail = context.obj.get('did_fail')
    issue_detected = context.obj.get('issue_detected')
    return did_fail or issue_detected
