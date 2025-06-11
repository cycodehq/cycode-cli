from typing import TYPE_CHECKING

from rich.syntax import Syntax

from cycode.cli import consts
from cycode.cli.console import _SYNTAX_HIGHLIGHT_THEME
from cycode.cli.printers.utils import is_git_diff_based_scan
from cycode.cli.utils.string_utils import get_position_in_line, obfuscate_text

if TYPE_CHECKING:
    from cycode.cli.models import Document
    from cycode.cyclient.models import Detection


def _get_code_segment_start_line(detection_line: int, lines_to_display_before: int) -> int:
    start_line = detection_line - lines_to_display_before
    return 0 if start_line < 0 else start_line


def get_detection_line(scan_type: str, detection: 'Detection') -> int:
    return (
        detection.detection_details.get('line', -1)
        if scan_type == consts.SECRET_SCAN_TYPE
        else detection.detection_details.get('line_in_file', -1) - 1
    )


def _get_syntax_highlighted_code(code: str, lexer: str, start_line: int, detection_line: int) -> Syntax:
    return Syntax(
        theme=_SYNTAX_HIGHLIGHT_THEME,
        code=code,
        lexer=lexer,
        line_numbers=True,
        word_wrap=True,
        dedent=True,
        tab_size=2,
        start_line=start_line + 1,
        highlight_lines={detection_line + 1},
    )


def _get_code_snippet_syntax_from_file(
    scan_type: str,
    detection: 'Detection',
    document: 'Document',
    lines_to_display_before: int,
    lines_to_display_after: int,
    obfuscate: bool,
) -> Syntax:
    detection_details = detection.detection_details
    detection_line = get_detection_line(scan_type, detection)
    start_line_index = _get_code_segment_start_line(detection_line, lines_to_display_before)
    detection_position = get_position_in_line(document.content, detection_details.get('start_position', -1))
    violation_length = detection_details.get('length', -1)

    code_lines_to_render = []
    document_content_lines = document.content.splitlines()
    total_lines_to_display = lines_to_display_before + 1 + lines_to_display_after

    for line_index in range(total_lines_to_display):
        current_line_index = start_line_index + line_index
        if current_line_index >= len(document_content_lines):
            break

        line_content = document_content_lines[current_line_index]

        line_with_detection = current_line_index == detection_line
        if scan_type == consts.SECRET_SCAN_TYPE and line_with_detection and obfuscate:
            violation = line_content[detection_position : detection_position + violation_length]
            code_lines_to_render.append(line_content.replace(violation, obfuscate_text(violation)))
        else:
            code_lines_to_render.append(line_content)

    code_to_render = '\n'.join(code_lines_to_render)
    return _get_syntax_highlighted_code(
        code=code_to_render,
        lexer=Syntax.guess_lexer(document.path, code=code_to_render),
        start_line=start_line_index,
        detection_line=detection_line,
    )


def _get_code_snippet_syntax_from_git_diff(
    scan_type: str, detection: 'Detection', document: 'Document', obfuscate: bool
) -> Syntax:
    detection_details = detection.detection_details
    detection_line = get_detection_line(scan_type, detection)
    detection_position = detection_details.get('start_position', -1)
    violation_length = detection_details.get('length', -1)

    line_content = document.content.splitlines()[detection_line]
    detection_position_in_line = get_position_in_line(document.content, detection_position)
    if scan_type == consts.SECRET_SCAN_TYPE and obfuscate:
        violation = line_content[detection_position_in_line : detection_position_in_line + violation_length]
        line_content = line_content.replace(violation, obfuscate_text(violation))

    return _get_syntax_highlighted_code(
        code=line_content,
        lexer='diff',
        start_line=detection_line,
        detection_line=detection_line,
    )


def get_code_snippet_syntax(
    scan_type: str,
    command_scan_type: str,
    detection: 'Detection',
    document: 'Document',
    lines_to_display_before: int = 1,
    lines_to_display_after: int = 1,
    obfuscate: bool = True,
) -> Syntax:
    if is_git_diff_based_scan(command_scan_type):
        # it will return syntax with just one line
        return _get_code_snippet_syntax_from_git_diff(scan_type, detection, document, obfuscate)

    return _get_code_snippet_syntax_from_file(
        scan_type, detection, document, lines_to_display_before, lines_to_display_after, obfuscate
    )
