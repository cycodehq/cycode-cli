import typer


def set_issue_detected(ctx: typer.Context, issue_detected: bool) -> None:
    ctx.obj['issue_detected'] = issue_detected


def is_scan_failed(ctx: typer.Context) -> bool:
    did_fail = ctx.obj.get('did_fail')
    issue_detected = ctx.obj.get('issue_detected')
    return did_fail or issue_detected
