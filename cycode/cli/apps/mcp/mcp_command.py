import asyncio
import json
import logging
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import Field

from cycode.cli.cli_types import McpTransportOption, ScanTypeOption
from cycode.cli.utils.sentry import add_breadcrumb
from cycode.logger import LoggersManager, get_logger

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.tools import Tool
except ImportError:
    raise ImportError(
        'Cycode MCP is not supported for your Python version. MCP support requires Python 3.10 or higher.'
    ) from None


_logger = get_logger('Cycode MCP')

_DEFAULT_RUN_COMMAND_TIMEOUT = 5 * 60

_FILES_TOOL_FIELD = Field(description='Files to scan, mapping file paths to their content')


def _is_debug_mode() -> bool:
    return LoggersManager.global_logging_level == logging.DEBUG


def _gen_random_id() -> str:
    return uuid.uuid4().hex


def _get_current_executable() -> str:
    """Get the current executable path for spawning subprocess."""
    if getattr(sys, 'frozen', False):  # pyinstaller bundle
        return sys.executable

    return 'cycode'


async def _run_cycode_command(*args: str, timeout: int = _DEFAULT_RUN_COMMAND_TIMEOUT) -> dict[str, Any]:
    """Run a cycode command asynchronously and return the parsed result.

    Args:
        *args: Command arguments to append after 'cycode -o json'
        timeout: Timeout in seconds (default 5 minutes)

    Returns:
        Dictionary containing the parsed JSON result or error information
    """
    verbose = ['-v'] if _is_debug_mode() else []
    cmd_args = [_get_current_executable(), *verbose, '-o', 'json', *list(args)]
    _logger.debug('Running Cycode CLI command: %s', ' '.join(cmd_args))

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd_args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        stdout_str = stdout.decode('UTF-8', errors='replace') if stdout else ''
        stderr_str = stderr.decode('UTF-8', errors='replace') if stderr else ''

        if _is_debug_mode():  # redirect debug output
            sys.stderr.write(stderr_str)

        if not stdout_str:
            return {'error': 'No output from command', 'stderr': stderr_str, 'returncode': process.returncode}

        try:
            return json.loads(stdout_str)
        except json.JSONDecodeError:
            return {
                'error': 'Failed to parse JSON output',
                'stdout': stdout_str,
                'stderr': stderr_str,
                'returncode': process.returncode,
            }
    except asyncio.TimeoutError:
        return {'error': f'Command timeout after {timeout} seconds'}
    except Exception as e:
        return {'error': f'Failed to run command: {e!s}'}


def _create_temp_files(files_content: dict[str, str]) -> list[str]:
    """Create temporary files from content and return their paths."""
    temp_dir = tempfile.mkdtemp(prefix='cycode_mcp_')
    temp_files = []

    _logger.debug('Creating temporary files in directory: %s', temp_dir)

    for file_path, content in files_content.items():
        safe_filename = f'{_gen_random_id()}_{Path(file_path).name}'
        temp_file_path = os.path.join(temp_dir, safe_filename)

        os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)

        _logger.debug('Creating temp file: %s', temp_file_path)
        with open(temp_file_path, 'w', encoding='UTF-8') as f:
            f.write(content)

        temp_files.append(temp_file_path)

    return temp_files


def _cleanup_temp_files(temp_files: list[str]) -> None:
    """Clean up temporary files and directories."""

    temp_dirs = set()
    for temp_file in temp_files:
        try:
            if os.path.exists(temp_file):
                _logger.debug('Removing temp file: %s', temp_file)
                os.remove(temp_file)
                temp_dirs.add(os.path.dirname(temp_file))
        except OSError as e:
            _logger.warning('Failed to remove temp file %s: %s', temp_file, e)

    for temp_dir in temp_dirs:
        try:
            if os.path.exists(temp_dir) and not os.listdir(temp_dir):
                _logger.debug('Removing temp directory: %s', temp_dir)
                os.rmdir(temp_dir)
        except OSError as e:
            _logger.warning('Failed to remove temp directory %s: %s', temp_dir, e)


async def _run_cycode_scan(scan_type: ScanTypeOption, temp_files: list[str]) -> dict[str, Any]:
    """Run cycode scan command and return the result."""
    return await _run_cycode_command(*['scan', '-t', str(scan_type), 'path', *temp_files])


async def _run_cycode_status() -> dict[str, Any]:
    """Run cycode status command and return the result."""
    return await _run_cycode_command('status')


async def _cycode_scan_tool(scan_type: ScanTypeOption, files: dict[str, str] = _FILES_TOOL_FIELD) -> str:
    _tool_call_id = _gen_random_id()
    _logger.info('Scan tool called, %s', {'scan_type': scan_type, 'call_id': _tool_call_id})

    if not files:
        _logger.error('No files provided for scan')
        return json.dumps({'error': 'No files provided'})

    temp_files = _create_temp_files(files)

    try:
        _logger.info(
            'Running Cycode scan, %s',
            {'scan_type': scan_type, 'files_count': len(temp_files), 'call_id': _tool_call_id},
        )
        result = await _run_cycode_scan(scan_type, temp_files)
        _logger.info('Scan completed, %s', {'scan_type': scan_type, 'call_id': _tool_call_id})
        return json.dumps(result, indent=2)
    except Exception as e:
        _logger.error('Scan failed, %s', {'scan_type': scan_type, 'call_id': _tool_call_id, 'error': str(e)})
        return json.dumps({'error': f'Scan failed: {e!s}'}, indent=2)
    finally:
        _cleanup_temp_files(temp_files)


async def cycode_secret_scan(files: dict[str, str] = _FILES_TOOL_FIELD) -> str:
    """Scan files for hardcoded secrets.

    Use this tool when you need to:
      - scan code for hardcoded secrets, API keys, passwords, tokens
      - verify that code doesn't contain exposed credentials
      - detect potential security vulnerabilities from secret exposure

    Args:
        files: Dictionary mapping file paths to their content

    Returns:
        JSON string containing scan results and any secrets found
    """
    return await _cycode_scan_tool(ScanTypeOption.SECRET, files)


async def cycode_sca_scan(files: dict[str, str] = _FILES_TOOL_FIELD) -> str:
    """Scan files for Software Composition Analysis (SCA) - vulnerabilities and license issues.

    Use this tool when you need to:
      - scan dependencies for known security vulnerabilities
      - check for license compliance issues
      - analyze third-party component risks
      - verify software supply chain security
      - review package.json, requirements.txt, pom.xml and other dependency files

    Args:
        files: Dictionary mapping file paths to their content

    Returns:
        JSON string containing scan results, vulnerabilities, and license issues found
    """
    return await _cycode_scan_tool(ScanTypeOption.SCA, files)


async def cycode_iac_scan(files: dict[str, str] = _FILES_TOOL_FIELD) -> str:
    """Scan files for Infrastructure as Code (IaC) misconfigurations.

    Use this tool when you need to:
      - scan Terraform, CloudFormation, Kubernetes YAML files
      - check for cloud security misconfigurations
      - verify infrastructure compliance and best practices
      - detect potential security issues in infrastructure definitions
      - review Docker files for security issues

    Args:
        files: Dictionary mapping file paths to their content

    Returns:
        JSON string containing scan results and any misconfigurations found
    """
    return await _cycode_scan_tool(ScanTypeOption.IAC, files)


async def cycode_sast_scan(files: dict[str, str] = _FILES_TOOL_FIELD) -> str:
    """Scan files for Static Application Security Testing (SAST) - code quality and security flaws.

    Use this tool when you need to:
      - scan source code for security vulnerabilities
      - detect code quality issues and potential bugs
      - check for insecure coding practices
      - verify code follows security best practices
      - find SQL injection, XSS, and other application security issues

    Args:
        files: Dictionary mapping file paths to their content

    Returns:
        JSON string containing scan results and any security flaws found
    """
    return await _cycode_scan_tool(ScanTypeOption.SAST, files)


async def cycode_status() -> str:
    """Get Cycode CLI version, authentication status, and configuration information.

    Use this tool when you need to:
      - verify Cycode CLI is properly configured
      - check authentication status
      - get CLI version information
      - troubleshoot setup issues
      - confirm service connectivity

    Returns:
        JSON string containing CLI status, version, and configuration details
    """
    _tool_call_id = _gen_random_id()
    _logger.info('Status tool called')

    try:
        _logger.info('Running Cycode status check, %s', {'call_id': _tool_call_id})
        result = await _run_cycode_status()
        _logger.info('Status check completed, %s', {'call_id': _tool_call_id})

        return json.dumps(result, indent=2)
    except Exception as e:
        _logger.error('Status check failed, %s', {'call_id': _tool_call_id, 'error': str(e)})
        return json.dumps({'error': f'Status check failed: {e!s}'}, indent=2)


def _create_mcp_server(host: str, port: int) -> FastMCP:
    """Create and configure the MCP server."""
    tools = [
        Tool.from_function(cycode_status),
        Tool.from_function(cycode_secret_scan),
        Tool.from_function(cycode_sca_scan),
        Tool.from_function(cycode_iac_scan),
        Tool.from_function(cycode_sast_scan),
    ]
    _logger.info('Creating MCP server with tools: %s', [tool.name for tool in tools])
    return FastMCP(
        'cycode',
        tools=tools,
        host=host,
        port=port,
        debug=_is_debug_mode(),
        log_level='DEBUG' if _is_debug_mode() else 'INFO',
    )


def _run_mcp_server(transport: McpTransportOption, host: str, port: int) -> None:
    """Run the MCP server using transport."""
    mcp = _create_mcp_server(host, port)
    mcp.run(transport=str(transport))  # type: ignore[arg-type]


def mcp_command(
    transport: Annotated[
        McpTransportOption,
        typer.Option(
            '--transport',
            '-t',
            case_sensitive=False,
            help='Transport type for the MCP server.',
        ),
    ] = McpTransportOption.STDIO,
    host: str = typer.Option(
        '127.0.0.1',
        '--host',
        '-H',
        help='Host address to bind the server (used only for non stdio transport).',
    ),
    port: int = typer.Option(
        8000,
        '--port',
        '-p',
        help='Port number to bind the server (used only for non stdio transport).',
    ),
) -> None:
    """:robot: Start the Cycode MCP (Model Context Protocol) server.

    The MCP server provides tools for scanning code with Cycode CLI:
    - cycode_secret_scan: Scan for hardcoded secrets
    - cycode_sca_scan: Software Composition Analysis scanning
    - cycode_iac_scan: Infrastructure as Code scanning
    - cycode_sast_scan: Static Application Security Testing scanning
    - cycode_status: Get Cycode CLI status (version, auth status) and configuration

    Examples:
        cycode mcp # Start with default transport (stdio)
        cycode mcp -t sse -p 8080 # Start with Server-Sent Events (SSE) transport on port 8080
    """
    add_breadcrumb('mcp')

    try:
        _run_mcp_server(transport, host, port)
    except Exception as e:
        _logger.error('MCP server error', exc_info=e)
        raise typer.Exit(1) from e
