import typer

from cycode.cli.apps.mcp.mcp_command import mcp_command

app = typer.Typer()

_mcp_command_docs = 'https://github.com/cycodehq/cycode-cli/blob/main/README.md#mcp-command-experiment'
_mcp_command_epilog = f'[bold]Documentation:[/] [link={_mcp_command_docs}]{_mcp_command_docs}[/link]'

app.command(
    name='mcp',
    short_help='[EXPERIMENT] Start the Cycode MCP (Model Context Protocol) server.',
    epilog=_mcp_command_epilog,
)(mcp_command)
