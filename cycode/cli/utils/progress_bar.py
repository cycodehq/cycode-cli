from abc import ABC, abstractmethod
from enum import auto
from typing import NamedTuple, Optional

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn

from cycode.cli.console import console
from cycode.cli.utils.enum_utils import AutoCountEnum
from cycode.logger import get_logger

# use LOGGING_LEVEL=DEBUG env var to see debug logs of this module
logger = get_logger('Progress Bar', control_level_in_runtime=False)


class ProgressBarSection(AutoCountEnum):
    def has_next(self) -> bool:
        return self.value < len(type(self)) - 1

    def next(self) -> 'ProgressBarSection':
        return type(self)(self.value + 1)


class ProgressBarSectionInfo(NamedTuple):
    section: ProgressBarSection
    label: str
    start_percent: int
    stop_percent: int
    initial: bool = False


_PROGRESS_BAR_LENGTH = 100
_PROGRESS_BAR_COLUMNS = (
    SpinnerColumn(),
    TextColumn('[progress.description]{task.description}'),
    TextColumn('{task.fields[right_side_label]}'),
    BarColumn(bar_width=None),
    TaskProgressColumn(),
    TimeElapsedColumn(),
)

ProgressBarSections = dict[ProgressBarSection, ProgressBarSectionInfo]


class ScanProgressBarSection(ProgressBarSection):
    PREPARE_LOCAL_FILES = auto()
    SCAN = auto()
    GENERATE_REPORT = auto()


SCAN_PROGRESS_BAR_SECTIONS: ProgressBarSections = {
    ScanProgressBarSection.PREPARE_LOCAL_FILES: ProgressBarSectionInfo(
        ScanProgressBarSection.PREPARE_LOCAL_FILES, 'Prepare local files', start_percent=0, stop_percent=5, initial=True
    ),
    ScanProgressBarSection.SCAN: ProgressBarSectionInfo(
        ScanProgressBarSection.SCAN, 'Scan in progress', start_percent=5, stop_percent=95
    ),
    ScanProgressBarSection.GENERATE_REPORT: ProgressBarSectionInfo(
        ScanProgressBarSection.GENERATE_REPORT, 'Generate report', start_percent=95, stop_percent=100
    ),
}


class SbomReportProgressBarSection(ProgressBarSection):
    PREPARE_LOCAL_FILES = auto()
    GENERATION = auto()
    RECEIVE_REPORT = auto()


SBOM_REPORT_PROGRESS_BAR_SECTIONS: ProgressBarSections = {
    SbomReportProgressBarSection.PREPARE_LOCAL_FILES: ProgressBarSectionInfo(
        SbomReportProgressBarSection.PREPARE_LOCAL_FILES,
        'Prepare local files',
        start_percent=0,
        stop_percent=30,
        initial=True,
    ),
    SbomReportProgressBarSection.GENERATION: ProgressBarSectionInfo(
        SbomReportProgressBarSection.GENERATION, 'Report generation in progress', start_percent=30, stop_percent=90
    ),
    SbomReportProgressBarSection.RECEIVE_REPORT: ProgressBarSectionInfo(
        SbomReportProgressBarSection.RECEIVE_REPORT, 'Receive report', start_percent=90, stop_percent=100
    ),
}


def _get_initial_section(progress_bar_sections: ProgressBarSections) -> ProgressBarSectionInfo:
    for section in progress_bar_sections.values():
        if section.initial:
            return section

    raise ValueError('No initial section found')


class BaseProgressBar(ABC):
    @abstractmethod
    def __init__(self, *args, **kwargs) -> None:
        pass

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def set_section_length(self, section: 'ProgressBarSection', length: int = 0) -> None: ...

    @abstractmethod
    def update(self, section: 'ProgressBarSection') -> None: ...

    @abstractmethod
    def update_right_side_label(self, label: Optional[str] = None) -> None: ...


class DummyProgressBar(BaseProgressBar):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def set_section_length(self, section: 'ProgressBarSection', length: int = 0) -> None:
        pass

    def update(self, section: 'ProgressBarSection') -> None:
        pass

    def update_right_side_label(self, label: Optional[str] = None) -> None:
        pass


class CompositeProgressBar(BaseProgressBar):
    def __init__(self, progress_bar_sections: ProgressBarSections) -> None:
        super().__init__()

        self._progress_bar_sections = progress_bar_sections

        self._section_lengths: dict[ProgressBarSection, int] = {}
        self._section_values: dict[ProgressBarSection, int] = {}

        self._current_section_value = 0
        self._current_section: ProgressBarSectionInfo = _get_initial_section(self._progress_bar_sections)
        self._current_right_side_label = ''

        self._progress_bar = Progress(*_PROGRESS_BAR_COLUMNS, console=console, refresh_per_second=5, transient=True)
        self._progress_bar_task_id = self._progress_bar.add_task(
            description=self._current_section.label,
            total=_PROGRESS_BAR_LENGTH,
            right_side_label=self._current_right_side_label,
        )

    def _progress_bar_update(self, advance: int = 0) -> None:
        self._progress_bar.update(
            self._progress_bar_task_id,
            advance=advance,
            description=self._current_section.label,
            right_side_label=self._current_right_side_label,
            refresh=True,
        )

    def start(self) -> None:
        self._progress_bar.start()

    def stop(self) -> None:
        self._progress_bar.stop()

    def set_section_length(self, section: 'ProgressBarSection', length: int = 0) -> None:
        logger.debug('Calling set_section_length, %s', {'section': str(section), 'length': length})
        self._section_lengths[section] = length

        if length == 0:
            self._skip_section(section)
        else:
            self._maybe_update_current_section()

    def _get_section_length(self, section: 'ProgressBarSection') -> int:
        section_info = self._progress_bar_sections[section]
        return section_info.stop_percent - section_info.start_percent

    def _skip_section(self, section: 'ProgressBarSection') -> None:
        self._progress_bar_update(self._get_section_length(section))
        self._maybe_update_current_section()

    def _increment_section_value(self, section: 'ProgressBarSection', value: int) -> None:
        self._section_values[section] = self._section_values.get(section, 0) + value
        logger.debug(
            'Calling _increment_section_value: %s +%s. %s/%s',
            section,
            value,
            self._section_values[section],
            self._section_lengths[section],
        )

    def _rerender_progress_bar(self) -> None:
        """Use to update label right after changing the progress bar section."""
        self._progress_bar_update()

    def _increment_progress(self, section: 'ProgressBarSection') -> None:
        increment_value = self._get_increment_progress_value(section)

        self._current_section_value += increment_value
        self._progress_bar_update(increment_value)

    def _maybe_update_current_section(self) -> None:
        if not self._current_section.section.has_next():
            return

        max_val = self._section_lengths.get(self._current_section.section, 0)
        cur_val = self._section_values.get(self._current_section.section, 0)
        if cur_val >= max_val:
            next_section = self._progress_bar_sections[self._current_section.section.next()]
            logger.debug(
                'Calling _update_current_section:  %s -> %s', self._current_section.section, next_section.section
            )

            self._current_section = next_section
            self._current_section_value = 0
            self._rerender_progress_bar()

    def _get_increment_progress_value(self, section: 'ProgressBarSection') -> int:
        max_val = self._section_lengths[section]
        cur_val = self._section_values[section]

        expected_value = round(self._get_section_length(section) * (cur_val / max_val))

        return expected_value - self._current_section_value

    def update(self, section: 'ProgressBarSection', value: int = 1) -> None:
        if section not in self._section_lengths:
            raise ValueError(f'{section} section is not initialized. Call set_section_length() first.')
        if section is not self._current_section.section:
            raise ValueError(
                f'Previous section is not completed yet. Complete {self._current_section.section} section first.'
            )

        self._increment_section_value(section, value)
        self._increment_progress(section)
        self._maybe_update_current_section()

    def update_right_side_label(self, label: Optional[str] = None) -> None:
        self._current_right_side_label = f'({label})' if label else ''
        self._progress_bar_update()


def get_progress_bar(*, hidden: bool, sections: ProgressBarSections) -> BaseProgressBar:
    if hidden:
        return DummyProgressBar()

    return CompositeProgressBar(sections)


if __name__ == '__main__':
    # TODO(MarshalX): cover with tests and remove this code
    import random
    import time

    bar = get_progress_bar(hidden=False, sections=SCAN_PROGRESS_BAR_SECTIONS)
    bar.start()

    for bar_section in ScanProgressBarSection:
        section_capacity = random.randint(500, 1000)  # noqa: S311
        bar.set_section_length(bar_section, section_capacity)

        for _i in range(section_capacity):
            time.sleep(0.01)
            bar.update_right_side_label(f'{bar_section} {_i}/{section_capacity}')
            bar.update(bar_section)

        bar.update_right_side_label()

    bar.stop()
