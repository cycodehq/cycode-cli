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
    PREPARE_LOCAL_FILES = auto()
    SCAN = auto()
    GENERATE_REPORT = auto()

    def has_next(self) -> bool:
        return self.value < len(ProgressBarSection) - 1

    def next(self) -> 'ProgressBarSection':
        return ProgressBarSection(self.value + 1)


class ProgressBarSectionInfo(NamedTuple):
    section: ProgressBarSection
    label: str
    start_percent: int
    stop_percent: int


_PROGRESS_BAR_LENGTH = 100

_PROGRESS_BAR_SECTIONS = {
    ProgressBarSection.PREPARE_LOCAL_FILES: ProgressBarSectionInfo(
        ProgressBarSection.PREPARE_LOCAL_FILES, 'Prepare local files', start_percent=0, stop_percent=5
    ),
    ProgressBarSection.SCAN: ProgressBarSectionInfo(
        ProgressBarSection.SCAN, 'Scan in progress', start_percent=5, stop_percent=95
    ),
    ProgressBarSection.GENERATE_REPORT: ProgressBarSectionInfo(
        ProgressBarSection.GENERATE_REPORT, 'Generate report', start_percent=95, stop_percent=100
    ),
}


def _get_section_length(section: 'ProgressBarSection') -> int:
    return _PROGRESS_BAR_SECTIONS[section].stop_percent - _PROGRESS_BAR_SECTIONS[section].start_percent


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
    def set_section_length(self, section: 'ProgressBarSection', length: int) -> None:
        ...

    @abstractmethod
    def update(self, section: 'ProgressBarSection') -> None:
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

    def set_section_length(self, section: 'ProgressBarSection', length: int) -> None:
        pass

    def update(self, section: 'ProgressBarSection') -> None:
        pass


class CompositeProgressBar(BaseProgressBar):
    def __init__(self) -> None:
        super().__init__()
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
        self._current_section: ProgressBarSectionInfo = _PROGRESS_BAR_SECTIONS[ProgressBarSection.PREPARE_LOCAL_FILES]

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

    def set_section_length(self, section: 'ProgressBarSection', length: int) -> None:
        logger.debug(f'set_section_length: {section} {length}')
        self._section_lengths[section] = length

        if length == 0:
            self._skip_section(section)
        else:
            self._maybe_update_current_section()

    def _skip_section(self, section: 'ProgressBarSection') -> None:
        self._progress_bar.update(_get_section_length(section))
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

    def _increment_progress(self, section: ProgressBarSection) -> None:
        increment_value = self._get_increment_progress_value(section)

        self._current_section_value += increment_value
        self._progress_bar.update(increment_value)

    def _maybe_update_current_section(self) -> None:
        if not self._current_section.section.has_next():
            return

        max_val = self._section_lengths.get(self._current_section.section, 0)
        cur_val = self._section_values.get(self._current_section.section, 0)
        if cur_val >= max_val:
            next_section = _PROGRESS_BAR_SECTIONS[self._current_section.section.next()]
            logger.debug(f'_update_current_section: {self._current_section.section} -> {next_section.section}')

            self._current_section = next_section
            self._current_section_value = 0
            self._rerender_progress_bar()

    def _get_increment_progress_value(self, section: 'ProgressBarSection') -> int:
        max_val = self._section_lengths[section]
        cur_val = self._section_values[section]

        expected_value = round(_get_section_length(section) * (cur_val / max_val))

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


def get_progress_bar(*, hidden: bool) -> BaseProgressBar:
    if hidden:
        return DummyProgressBar()

    return CompositeProgressBar()


if __name__ == '__main__':
    # TODO(MarshalX): cover with tests and remove this code
    import random
    import time

    bar = get_progress_bar(hidden=False)
    bar.start()

    for bar_section in ProgressBarSection:
        section_capacity = random.randint(500, 1000)  # noqa: S311
        bar.set_section_length(bar_section, section_capacity)

        for _i in range(section_capacity):
            time.sleep(0.01)
            bar.update(bar_section)

    bar.stop()
