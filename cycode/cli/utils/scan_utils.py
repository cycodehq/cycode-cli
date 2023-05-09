import click


def is_scan_failed(context: click.Context):
    did_fail = context.obj.get("did_fail")
    issue_detected = context.obj.get("issue_detected")
    return did_fail or issue_detected
