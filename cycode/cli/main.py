from multiprocessing import freeze_support

from cycode.cli.commands.main_cli import main_cli
from cycode.cli.sentry import add_breadcrumb, init_sentry

if __name__ == '__main__':
    # DO NOT REMOVE OR MOVE THIS LINE
    # this is required to support multiprocessing in executables files packaged with PyInstaller
    # see https://pyinstaller.org/en/latest/common-issues-and-pitfalls.html#multi-processing
    freeze_support()

    init_sentry()
    add_breadcrumb('cycode')

    main_cli()
