import click
from halo import Halo


def is_scan_failed(context: click.Context):
    did_fail = context.obj.get("did_fail")
    issue_detected = context.obj.get("issue_detected")
    return did_fail or issue_detected


def create_spinner_and_echo(spinner_message) -> Halo:
    spinner = create_spinner(spinner_message)
    click.echo()
    return spinner


def create_spinner(spinner_message):
    spinner = Halo(spinner='dots')
    spinner.start(spinner_message)
    return spinner
