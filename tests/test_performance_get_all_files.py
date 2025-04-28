import glob
import logging
import os
import timeit
from pathlib import Path
from typing import Union

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def filter_files(paths: list[Union[Path, str]]) -> list[str]:
    return [str(path) for path in paths if os.path.isfile(path)]


def get_all_files_glob(path: Union[Path, str]) -> list[str]:
    # DOESN'T RETURN HIDDEN FILES. CAN'T BE USED
    # and doesn't show the best performance
    if not str(path).endswith(os.sep):
        path = f'{path}{os.sep}'

    return filter_files(glob.glob(f'{path}**', recursive=True))


def get_all_files_walk(path: str) -> list[str]:
    files = []

    for root, _, filenames in os.walk(path):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    return files


def get_all_files_listdir(path: str) -> list[str]:
    files = []

    def _(sub_path: str) -> None:
        items = os.listdir(sub_path)

        for item in items:
            item_path = os.path.join(sub_path, item)

            if os.path.isfile(item_path):
                files.append(item_path)
            elif os.path.isdir(item_path):
                _(item_path)

    _(path)
    return files


def get_all_files_rglob(path: str) -> list[str]:
    return filter_files(list(Path(path).rglob(r'*')))


def test_get_all_files_performance(test_files_path: str) -> None:
    results: dict[str, tuple[int, float]] = {}
    for func in {
        get_all_files_rglob,
        get_all_files_listdir,
        get_all_files_walk,
    }:
        name = func.__name__
        start_time = timeit.default_timer()

        files_count = len(func(test_files_path))

        executed_time = timeit.default_timer() - start_time
        results[name] = (files_count, executed_time)

        logger.info('Time result %s: %s', name, executed_time)
        logger.info('Files count %s: %s', name, files_count)

    files_counts = [result[0] for result in results.values()]
    assert len(set(files_counts)) == 1  # all should be equal

    logger.info('Benchmark TOP with (%s) files:', files_counts[0])
    for func_name, result in sorted(results.items(), key=lambda x: x[1][1]):
        logger.info('- %s: %s', func_name, result[1])

    # according to my (MarshalX) local tests, the fastest is get_all_files_walk


if __name__ == '__main__':
    # provide a path with thousands of files
    huge_dir_path = '/Users/ilyasiamionau/projects/cycode/'
    test_get_all_files_performance(huge_dir_path)

    # Output:
    # INFO:__main__:Benchmark TOP with (94882) files:
    # INFO:__main__:- get_all_files_walk: 0.717258458
    # INFO:__main__:- get_all_files_listdir: 1.4648628330000002
    # INFO:__main__:- get_all_files_rglob: 2.368291458
