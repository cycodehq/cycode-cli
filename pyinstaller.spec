# -*- mode: python ; coding: utf-8 -*-
# Run `poetry run pyinstaller pyinstaller.spec` to generate the binary.
# Set the env var `CYCODE_ONEDIR_MODE` to generate a single directory instead of a single file.

_INIT_FILE_PATH = os.path.join('cycode', '__init__.py')
_CODESIGN_IDENTITY = os.environ.get('APPLE_CERT_NAME')
_ONEDIR_MODE = os.environ.get('CYCODE_ONEDIR_MODE') is not None

# save the prev content of __init__ file
with open(_INIT_FILE_PATH, 'r', encoding='UTF-8') as file:
    prev_content = file.read()

import dunamai as _dunamai

VERSION_PLACEHOLDER = '0.0.0'
CLI_VERSION = _dunamai.get_version('cycode', first_choice=_dunamai.Version.from_git).serialize(
    metadata=False, bump=True, style=_dunamai.Style.Pep440
)

# write the version from Git Tag to freeze the value and don't depend on Git
with open(_INIT_FILE_PATH, 'w', encoding='UTF-8') as file:
    file.write(prev_content.replace(VERSION_PLACEHOLDER, CLI_VERSION))

# Top-level subapp modules are loaded lazily via importlib.import_module() in
# cycode/cli/app.py to keep startup fast on hot paths (e.g. ai-guardrails scan).
# PyInstaller's static analyzer can't see those imports, so list them explicitly.
_hiddenimports = [
    'cycode.cli.apps.ai_guardrails',
    'cycode.cli.apps.ai_remediation',
    'cycode.cli.apps.auth',
    'cycode.cli.apps.configure',
    'cycode.cli.apps.ignore',
    'cycode.cli.apps.report',
    'cycode.cli.apps.report_import',
    'cycode.cli.apps.scan',
    'cycode.cli.apps.status',
    'cycode.cli.apps.mcp',
]

a = Analysis(
    scripts=['cycode/cli/main.py'],
    excludes=['tests', 'setuptools', 'pkg_resources'],
    hiddenimports=_hiddenimports,
)

if platform.system() == 'Darwin':
    try:
        openssl_lib = os.path.join(
            subprocess.check_output(['brew', '--prefix', 'openssl@3'], text=True).strip(), 'lib'
        )
        brew_ssl = os.path.join(openssl_lib, 'libssl.3.dylib')
        brew_crypto = os.path.join(openssl_lib, 'libcrypto.3.dylib')

        if os.path.exists(brew_ssl) and os.path.exists(brew_crypto):
            a.binaries = [
                binary for binary in a.binaries
                if 'libssl' not in binary[0] and 'libcrypto' not in binary[0]
            ]
            a.binaries.append(('libssl.3.dylib', brew_ssl, 'BINARY'))
            a.binaries.append(('libcrypto.3.dylib', brew_crypto, 'BINARY'))
            print(f'Replaced collected OpenSSL dylibs with Homebrew ones from {openssl_lib}')
        else:
            print(f'Warning: Homebrew OpenSSL dylibs not found in {openssl_lib}')
    except Exception as e:
        print(f'Warning: Could not override OpenSSL binaries: {e}')

exe_args = [PYZ(a.pure), a.scripts, a.binaries, a.datas]
if _ONEDIR_MODE:
    exe_args = [PYZ(a.pure), a.scripts]

exe = EXE(
    *exe_args,
    name='cycode-cli',
    exclude_binaries=bool(_ONEDIR_MODE),
    target_arch=None,
    codesign_identity=_CODESIGN_IDENTITY,
    entitlements_file='entitlements.plist',
)

if _ONEDIR_MODE:
    coll = COLLECT(exe, a.binaries, a.datas, name='cycode-cli')

# rollback the prev content of the __init__ file
with open(_INIT_FILE_PATH, 'w', encoding='UTF-8') as file:
    file.write(prev_content)
