from multiprocessing import freeze_support

from cycode.cli.commands.main_cli import main_cli

if __name__ == '__main__':
    # DO NOT REMOVE OR MOVE THIS LINE
    # this is required to support multiprocessing in executables files packaged with PyInstaller
    # see https://pyinstaller.org/en/latest/common-issues-and-pitfalls.html#multi-processing
    freeze_support()

    main_cli()
