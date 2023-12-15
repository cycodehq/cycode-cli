# -*- mode: python ; coding: utf-8 -*-
# Run `poetry run pyinstaller pyinstaller.spec` to generate the binary.


INIT_FILE_PATH = os.path.join('cycode', '__init__.py')

# save the prev content of __init__ file
with open(INIT_FILE_PATH, 'r', encoding='UTF-8') as file:
    prev_content = file.read()

import dunamai as _dunamai
VERSION_PLACEHOLDER = '0.0.0'
CLI_VERSION = _dunamai.get_version('cycode', first_choice=_dunamai.Version.from_git).serialize(
    metadata=False, bump=True, style=_dunamai.Style.Pep440
)

# write version from Git Tag to freeze the value and don't depend on Git
with open(INIT_FILE_PATH, 'w', encoding='UTF-8') as file:
    file.write(prev_content.replace(VERSION_PLACEHOLDER, CLI_VERSION))

a = Analysis(
    scripts=['cycode/cli/main.py'],
    datas=[('cycode/cli/config.yaml', 'cycode/cli'), ('cycode/cyclient/config.yaml', 'cycode/cyclient')],
    excludes=['tests'],
)
pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='cycode',
    debug=False,
    strip=True,
    runtime_tmpdir=None,
    target_arch=None,
    disable_windowed_traceback=True,
)

# rollback the prev content of the __init__ file
with open(INIT_FILE_PATH, 'w', encoding='UTF-8') as file:
    file.write(prev_content)
