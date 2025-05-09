import io
from typing import TYPE_CHECKING, ClassVar, Optional

import typer
from rich.console import Console

from cycode.cli import consts
from cycode.cli.cli_types import ExportTypeOption
from cycode.cli.console import console, console_err
from cycode.cli.exceptions.custom_exceptions import CycodeError
from cycode.cli.models import CliError, CliResult
from cycode.cli.printers.json_printer import JsonPrinter
from cycode.cli.printers.rich_printer import RichPrinter
from cycode.cli.printers.tables.sca_table_printer import ScaTablePrinter
from cycode.cli.printers.tables.table_printer import TablePrinter
from cycode.cli.printers.text_printer import TextPrinter

if TYPE_CHECKING:
    from pathlib import Path

    from cycode.cli.models import LocalScanResult
    from cycode.cli.printers.tables.table_printer_base import PrinterBase


class ConsolePrinter:
    _AVAILABLE_PRINTERS: ClassVar[dict[str, type['PrinterBase']]] = {
        'rich': RichPrinter,
        'text': TextPrinter,
        'json': JsonPrinter,
        'table': TablePrinter,
        # overrides:
        'table_sca': ScaTablePrinter,
    }

    def __init__(
        self,
        ctx: typer.Context,
        console_override: Optional['Console'] = None,
        console_err_override: Optional['Console'] = None,
        output_type_override: Optional[str] = None,
    ) -> None:
        self.ctx = ctx
        self.console = console_override or console
        self.console_err = console_err_override or console_err
        self.output_type = output_type_override or self.ctx.obj.get('output')

        self.export_type: Optional[str] = None
        self.export_file: Optional[Path] = None
        self.console_record: Optional[ConsolePrinter] = None

    @property
    def scan_type(self) -> str:
        return self.ctx.obj.get('scan_type')

    @property
    def aggregation_report_url(self) -> str:
        return self.ctx.obj.get('aggregation_report_url')

    @property
    def printer(self) -> 'PrinterBase':
        printer_class = self._AVAILABLE_PRINTERS.get(self.output_type)

        composite_printer = self._AVAILABLE_PRINTERS.get(f'{self.output_type}_{self.scan_type}')
        if composite_printer:
            printer_class = composite_printer

        if not printer_class:
            raise CycodeError(f'"{self.output_type}" output type is not supported.')

        return printer_class(self.ctx, self.console, self.console_err)

    def update_ctx(self, ctx: 'typer.Context') -> None:
        self.ctx = ctx

    def enable_recording(self, export_type: str, export_file: 'Path') -> None:
        if self.console_record is None:
            self.export_file = export_file
            self.export_type = export_type

            self.console_record = ConsolePrinter(
                self.ctx,
                console_override=Console(record=True, file=io.StringIO()),
                console_err_override=Console(stderr=True, record=True, file=io.StringIO()),
                output_type_override='json' if self.export_type == 'json' else self.output_type,
            )

    def print_scan_results(
        self,
        local_scan_results: list['LocalScanResult'],
        errors: Optional[dict[str, 'CliError']] = None,
    ) -> None:
        if self.console_record:
            self.console_record.print_scan_results(local_scan_results, errors)
        self.printer.print_scan_results(local_scan_results, errors)

    def print_result(self, result: CliResult) -> None:
        if self.console_record:
            self.console_record.print_result(result)
        self.printer.print_result(result)

    def print_error(self, error: CliError) -> None:
        if self.console_record:
            self.console_record.print_error(error)
        self.printer.print_error(error)

    def print_exception(self, e: Optional[BaseException] = None, force_print: bool = False) -> None:
        """Print traceback message in stderr if verbose mode is set."""
        if force_print or self.ctx.obj.get('verbose', False):
            if self.console_record:
                self.console_record.print_exception(e)
            self.printer.print_exception(e)

    def export(self) -> None:
        if self.console_record is None:
            raise CycodeError('Console recording was not enabled. Cannot export.')

        export_file = self.export_file
        if not export_file.suffix:
            # resolve file extension based on the export type if not provided in the file name
            export_file = export_file.with_suffix(f'.{self.export_type.lower()}')

        export_file = str(export_file)
        if self.export_type is ExportTypeOption.HTML:
            self.console_record.console.save_html(export_file)
        elif self.export_type is ExportTypeOption.SVG:
            self.console_record.console.save_svg(export_file, title=consts.APP_NAME)
        elif self.export_type is ExportTypeOption.JSON:
            with open(export_file, 'w', encoding='UTF-8') as f:
                self.console_record.console.file.seek(0)
                f.write(self.console_record.console.file.read())
        else:
            raise CycodeError(f'Export type "{self.export_type}" is not supported.')

        export_format_msg = f'{self.export_type.upper()} format'
        if self.export_type in {ExportTypeOption.HTML, ExportTypeOption.SVG}:
            export_format_msg += f' with {self.output_type.upper()} output type'

        clickable_path = f'[link=file://{self.export_file}]{self.export_file}[/link]'
        self.console.print(f'[b green]Cycode CLI output exported to {clickable_path} in {export_format_msg}[/]')

    @property
    def is_recording(self) -> bool:
        return self.console_record is not None

    @property
    def is_json_printer(self) -> bool:
        return isinstance(self.printer, JsonPrinter)

    @property
    def is_table_printer(self) -> bool:
        return isinstance(self.printer, TablePrinter)

    @property
    def is_text_printer(self) -> bool:
        return isinstance(self.printer, TextPrinter)

    @property
    def is_rich_printer(self) -> bool:
        return isinstance(self.printer, RichPrinter)
