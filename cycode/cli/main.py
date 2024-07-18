from multiprocessing import freeze_support

# DO NOT REMOVE OR MOVE THIS LINE
# this is required to use certificates system store with requests packaged with PyInstaller
import pip_system_certs.wrapt_requests  # noqa: F401

from cycode.cli.commands.main_cli import main_cli

if __name__ == '__main__':
    # DO NOT REMOVE OR MOVE THIS LINE
    # this is required to support multiprocessing in executables files packaged with PyInstaller
    # see https://pyinstaller.org/en/latest/common-issues-and-pitfalls.html#multi-processing
    freeze_support()

    main_cli()
