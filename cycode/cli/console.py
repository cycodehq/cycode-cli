import os
from typing import TYPE_CHECKING, Optional

from rich.console import Console, RenderResult
from rich.markdown import Heading, Markdown
from rich.text import Text

if TYPE_CHECKING:
    from rich.console import ConsoleOptions

console_out = Console()
console_err = Console(stderr=True)

console = console_out  # alias


def is_dark_console() -> Optional[bool]:
    """Detect if the console is dark or light.

    This function checks the environment variables and terminal type to determine if the console is dark or light.

    Used approaches:
    1. Check the `LC_DARK_BG` environment variable.
    2. Check the `COLORFGBG` environment variable for background color.

    And it still could be wrong in some cases.

    TODO(MarshalX): migrate to https://github.com/dalance/termbg when someone will implement it for Python.
    """
    dark = None

    dark_bg = os.environ.get('LC_DARK_BG')
    if dark_bg is not None:
        return dark_bg != '0'

    # If BG color in {0, 1, 2, 3, 4, 5, 6, 8} then dark, else light.
    try:
        color = os.environ.get('COLORFGBG')
        *_, bg = color.split(';')
        bg = int(bg)
        dark = bool(0 <= bg <= 6 or bg == 8)
    except Exception:  # noqa: S110
        pass

    return dark


_SYNTAX_HIGHLIGHT_DARK_THEME = 'monokai'
_SYNTAX_HIGHLIGHT_LIGHT_THEME = 'default'

# when we could not detect it, use dark theme as most terminals are dark
_SYNTAX_HIGHLIGHT_THEME = _SYNTAX_HIGHLIGHT_LIGHT_THEME if is_dark_console() is False else _SYNTAX_HIGHLIGHT_DARK_THEME


class CycodeHeading(Heading):
    """Custom Rich Heading for Markdown.

    Changes:
    - remove justify to 'center'
    - remove the box for h1
    """

    def __rich_console__(self, console: 'Console', options: 'ConsoleOptions') -> RenderResult:
        if self.tag == 'h2':
            yield Text('')
        yield self.text


Markdown.elements['heading_open'] = CycodeHeading
