import typer

from cycode.cli.apps.scan.commit_history.commit_history_command import commit_history_command
from cycode.cli.apps.scan.path.path_command import path_command
from cycode.cli.apps.scan.pre_commit.pre_commit_command import pre_commit_command
from cycode.cli.apps.scan.pre_receive.pre_receive_command import pre_receive_command
from cycode.cli.apps.scan.repository.repository_command import repository_command
from cycode.cli.apps.scan.scan_command import scan_command, scan_command_result_callback

app = typer.Typer(name='scan', no_args_is_help=True)

_scan_command_docs = 'https://github.com/cycodehq/cycode-cli/blob/main/README.md#scan-command'
_scan_command_epilog = f'[bold]Documentation:[/] [link={_scan_command_docs}]{_scan_command_docs}[/link]'

app.callback(
    short_help='Scan the content for Secrets, IaC, SCA, and SAST violations.',
    result_callback=scan_command_result_callback,
    epilog=_scan_command_epilog,
)(scan_command)

app.command(name='path', short_help='Scan the files in the paths provided in the command.')(path_command)
app.command(name='repository', short_help='Scan the Git repository included files.')(repository_command)
app.command(name='commit-history', short_help='Scan commit history or perform diff scanning between specific commits.')(
    commit_history_command
)
app.command(
    name='pre-commit',
    short_help='Use this command in pre-commit hook to scan any content that was not committed yet.',
    rich_help_panel='Automation commands',
)(pre_commit_command)
app.command(
    name='pre-receive',
    short_help='Use this command in pre-receive hook '
    'to scan commits on the server side before pushing them to the repository.',
    rich_help_panel='Automation commands',
)(pre_receive_command)

# backward compatibility
app.command(hidden=True, name='commit_history')(commit_history_command)
app.command(hidden=True, name='pre_commit')(pre_commit_command)
app.command(hidden=True, name='pre_receive')(pre_receive_command)
