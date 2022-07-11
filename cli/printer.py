import click
import math
from cli.models import DetectionDetails
from cli.config import config
from cli.consts import SECRET_SCAN_TYPE
from cli.utils.string_utils import obfuscate_text

import colorama


@click.pass_context
def print_detections(context: click.Context, detection_details: DetectionDetails):
    lines_to_display = config['result_printer']['lines_to_display']
    show_secret = context.obj['show_secret']
    scan_type = context.obj['scan_type']
    document = detection_details.document
    for detection in detection_details.detections:
        detection_name = detection.type if scan_type == SECRET_SCAN_TYPE else detection.message
        detection_sha = detection.detection_details.get('sha512')
        detection_sha_message = f'\nSecret SHA: {detection_sha}' if detection_sha else ''
        detection_commit_id = detection.detection_details.get('commit_id')
        detection_commit_id_message = f'\nCommit SHA: {detection_commit_id}' if detection_commit_id else ''
        click.echo(
            f'⛔  Found issue of type: {click.style(detection_name, fg="bright_red", bold=True)} (rule ID: {detection.detection_rule_id}) in file: {click.format_filename(detection_details.document.path)} ' +
            f'{detection_sha_message}{detection_commit_id_message}  ⛔ ')

        detection_line = try_get_int("line" if scan_type == SECRET_SCAN_TYPE else "line_in_file",
                                     detection.detection_details)
        detection_position = try_get_int("start_position", detection.detection_details)

        lines = detection_details.document.content.splitlines()
        start_line = detection_line - math.ceil(lines_to_display / 2)
        if start_line < 0:
            start_line = 0

        click.echo()
        for i in range(lines_to_display):
            current_line_index = start_line + i
            if current_line_index >= len(lines):
                break

            current_line = lines[current_line_index]
            if current_line_index == detection_line:
                position = get_position_in_line(detection_details.document.content, detection_position)
                click.echo(
                    f"{get_line_number_style(current_line_index+1)} {get_line_style(current_line, document.is_git_diff_format, position, detection.detection_details.get('length'), show_secret, scan_type)}")
            else:
                click.echo(
                    f'{get_line_number_style(current_line_index+1)} {get_line_style(current_line, document.is_git_diff_format, scan_type=scan_type)}')
        click.echo()


def get_position_in_line(text: str, position: int) -> int:
    return position - text.rfind('\n', 0, position) - 1


def get_line_number_style(line_number: int):
    return f'{click.style(str(line_number), fg="white", bold=False)} {click.style("|", fg="red", bold=False)}'


def get_line_style(line: str, is_git_diff: bool, start_position: int = -1,
                   length: int = None, show_secret: bool = False, scan_type: str = 'secret'):
    if start_position >= 0 and scan_type == SECRET_SCAN_TYPE:
        violation = line[start_position: start_position + length]
        if not show_secret:
            violation = obfuscate_text(violation)
        return f'{get_line_style(line[0: start_position], is_git_diff, scan_type=scan_type)}{click.style(violation, underline=True, bold=False)}{get_line_style(line[start_position + length:], is_git_diff, scan_type=scan_type)}'

    if not is_git_diff:
        return click.style(line, fg='white', bold=False)

    if line.startswith('+'):
        return click.style(line, fg='green', bold=False)

    if line.startswith('-'):
        return click.style(line, fg='red', bold=False)

    return click.style(line, fg='white', bold=False)


def try_get_int(key, dict):
    return dict[key] if key in dict else -1
