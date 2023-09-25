from abc import ABC, abstractmethod
from enum import auto
from typing import TYPE_CHECKING, Dict, NamedTuple, Optional

import click

from cycode.cli.utils.enum_utils import AutoCountEnum
from cycode.cyclient.config import get_logger

if TYPE_CHECKING:
    from click._termui_impl import ProgressBar
    from click.termui import V as ProgressBarValue


logger = get_logger('progress bar')


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

ProgressBarSections = Dict[ProgressBarSection, ProgressBarSectionInfo]


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
    def __enter__(self) -> 'BaseProgressBar':
        ...

    @abstractmethod
    def __exit__(self, *args, **kwargs) -> None:
        ...

    @abstractmethod
    def start(self) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...

    @abstractmethod
    def set_section_length(self, section: 'ProgressBarSection', length: int = 0) -> None:
        ...

    @abstractmethod
    def update(self, section: 'ProgressBarSection') -> None:
        ...

    @abstractmethod
    def update_label(self, label: Optional[str] = None) -> None:
        ...


class DummyProgressBar(BaseProgressBar):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def __enter__(self) -> 'DummyProgressBar':
        return self

    def __exit__(self, *args, **kwargs) -> None:
        pass

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def set_section_length(self, section: 'ProgressBarSection', length: int = 0) -> None:
        pass

    def update(self, section: 'ProgressBarSection') -> None:
        pass

    def update_label(self, label: Optional[str] = None) -> None:
        pass


class CompositeProgressBar(BaseProgressBar):
    def __init__(self, progress_bar_sections: ProgressBarSections) -> None:
        super().__init__()

        self._progress_bar_sections = progress_bar_sections

        self._progress_bar_context_manager = click.progressbar(
            length=_PROGRESS_BAR_LENGTH,
            item_show_func=self._progress_bar_item_show_func,
            update_min_steps=0,
        )
        self._progress_bar: Optional['ProgressBar'] = None
        self._run = False

        self._section_lengths: Dict[ProgressBarSection, int] = {}
        self._section_values: Dict[ProgressBarSection, int] = {}

        self._current_section_value = 0
        self._current_section: ProgressBarSectionInfo = _get_initial_section(self._progress_bar_sections)

    def __enter__(self) -> 'CompositeProgressBar':
        self._progress_bar = self._progress_bar_context_manager.__enter__()
        self._run = True
        return self

    def __exit__(self, *args, **kwargs) -> None:
        self._progress_bar_context_manager.__exit__(*args, **kwargs)
        self._run = False

    def start(self) -> None:
        if not self._run:
            self.__enter__()

    def stop(self) -> None:
        if self._run:
            self.__exit__(None, None, None)

    def set_section_length(self, section: 'ProgressBarSection', length: int = 0) -> None:
        logger.debug(f'set_section_length: {section} {length}')
        self._section_lengths[section] = length

        if length == 0:
            self._skip_section(section)
        else:
            self._maybe_update_current_section()

    def _get_section_length(self, section: 'ProgressBarSection') -> int:
        section_info = self._progress_bar_sections[section]
        return section_info.stop_percent - section_info.start_percent

    def _skip_section(self, section: 'ProgressBarSection') -> None:
        self._progress_bar.update(self._get_section_length(section))
        self._maybe_update_current_section()

    def _increment_section_value(self, section: 'ProgressBarSection', value: int) -> None:
        self._section_values[section] = self._section_values.get(section, 0) + value
        logger.debug(
            f'_increment_section_value: {section} +{value}. '
            f'{self._section_values[section]}/{self._section_lengths[section]}'
        )

    def _rerender_progress_bar(self) -> None:
        """Used to update label right after changing the progress bar section."""
        self._progress_bar.update(0)

    def _increment_progress(self, section: 'ProgressBarSection') -> None:
        increment_value = self._get_increment_progress_value(section)

        self._current_section_value += increment_value
        self._progress_bar.update(increment_value)

    def _maybe_update_current_section(self) -> None:
        if not self._current_section.section.has_next():
            return

        max_val = self._section_lengths.get(self._current_section.section, 0)
        cur_val = self._section_values.get(self._current_section.section, 0)
        if cur_val >= max_val:
            next_section = self._progress_bar_sections[self._current_section.section.next()]
            logger.debug(f'_update_current_section: {self._current_section.section} -> {next_section.section}')

            self._current_section = next_section
            self._current_section_value = 0
            self._rerender_progress_bar()

    def _get_increment_progress_value(self, section: 'ProgressBarSection') -> int:
        max_val = self._section_lengths[section]
        cur_val = self._section_values[section]

        expected_value = round(self._get_section_length(section) * (cur_val / max_val))

        return expected_value - self._current_section_value

    def _progress_bar_item_show_func(self, _: Optional['ProgressBarValue'] = None) -> str:
        return self._current_section.label

    def update(self, section: 'ProgressBarSection', value: int = 1) -> None:
        if not self._progress_bar:
            raise ValueError('Progress bar is not initialized. Call start() first or use "with" statement.')

        if section not in self._section_lengths:
            raise ValueError(f'{section} section is not initialized. Call set_section_length() first.')
        if section is not self._current_section.section:
            raise ValueError(
                f'Previous section is not completed yet. Complete {self._current_section.section} section first.'
            )

        self._increment_section_value(section, value)
        self._increment_progress(section)
        self._maybe_update_current_section()

    def update_label(self, label: Optional[str] = None) -> None:
        if not self._progress_bar:
            raise ValueError('Progress bar is not initialized. Call start() first or use "with" statement.')

        self._progress_bar.label = label or ''
        self._progress_bar.render_progress()


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
            bar.update_label(f'{bar_section} {_i}/{section_capacity}')
            bar.update(bar_section)

        bar.update_label()

    bar.stop()
