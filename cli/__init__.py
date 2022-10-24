from pathlib import Path


def get_version():
    this_directory = Path(__file__).parent
    root_project_directory = Path(this_directory).parent
    return (root_project_directory / "VERSION.txt").read_text(encoding='utf-8')


__version__ = get_version()

