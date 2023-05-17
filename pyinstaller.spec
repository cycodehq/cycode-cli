# -*- mode: python ; coding: utf-8 -*-
# Run `poetry run pyinstaller pyinstaller.spec` to generate the binary.


block_cipher = None

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
    ['cycode/cli/main.py'],
    pathex=[],
    binaries=[],
    datas=[('cycode/cli/config.yaml', 'cycode/cli'), ('cycode/cyclient/config.yaml', 'cycode/cyclient')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tests'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='cycode',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# rollback the prev content of the __init__ file
with open(INIT_FILE_PATH, 'w', encoding='UTF-8') as file:
    file.write(prev_content)
