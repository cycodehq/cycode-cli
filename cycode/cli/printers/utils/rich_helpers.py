from typing import TYPE_CHECKING

from rich.columns import Columns
from rich.markdown import Markdown
from rich.panel import Panel

from cycode.cli.console import console

if TYPE_CHECKING:
    from rich.console import RenderableType


def get_panel(renderable: 'RenderableType', title: str) -> Panel:
    return Panel(
        renderable,
        title=title,
        title_align='left',
        border_style='dim',
    )


def get_markdown_panel(markdown_text: str, title: str) -> Panel:
    return get_panel(
        Markdown(markdown_text.strip()),
        title=title,
    )


def get_columns_in_1_to_3_ratio(left: 'Panel', right: 'Panel', panel_border_offset: int = 5) -> Columns:
    terminal_width = console.width
    one_third_width = terminal_width // 3
    two_thirds_width = terminal_width - one_third_width - panel_border_offset

    left.width = one_third_width
    right.width = two_thirds_width

    return Columns([left, right])
