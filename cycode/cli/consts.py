PROGRAM_NAME = 'cycode'
APP_NAME = 'CycodeCLI'
CLI_CONTEXT_SETTINGS = {'terminal_width': 10**9, 'max_content_width': 10**9, 'help_option_names': ['-h', '--help']}

PRE_COMMIT_COMMAND_SCAN_TYPE = 'pre-commit'
PRE_COMMIT_COMMAND_SCAN_TYPE_OLD = 'pre_commit'
PRE_RECEIVE_COMMAND_SCAN_TYPE = 'pre-receive'
PRE_RECEIVE_COMMAND_SCAN_TYPE_OLD = 'pre_receive'
COMMIT_HISTORY_COMMAND_SCAN_TYPE = 'commit-history'
COMMIT_HISTORY_COMMAND_SCAN_TYPE_OLD = 'commit_history'

SECRET_SCAN_TYPE = 'secret'
IAC_SCAN_TYPE = 'iac'
SCA_SCAN_TYPE = 'sca'
SAST_SCAN_TYPE = 'sast'

IAC_SCAN_SUPPORTED_FILE_EXTENSIONS = ('.tf', '.tf.json', '.json', '.yaml', '.yml', '.dockerfile', '.containerfile')
IAC_SCAN_SUPPORTED_FILE_PREFIXES = ('dockerfile', 'containerfile')

SECRET_SCAN_FILE_EXTENSIONS_TO_IGNORE = (
    '.DS_Store',
    '.bmp',
    '.gif',
    '.ico',
    '.tif',
    '.tiff',
    '.webp',
    '.mp3',
    '.mp4',
    '.mkv',
    '.avi',
    '.mov',
    '.mpg',
    '.mpeg',
    '.wav',
    '.vob',
    '.aac',
    '.flac',
    '.ogg',
    '.mka',
    '.wma',
    '.wmv',
    '.psd',
    '.ai',
    '.model',
    '.lock',
    '.css',
    '.pdf',
    '.odt',
    '.iso',
)

SCA_CONFIGURATION_SCAN_SUPPORTED_FILES = (  # keep in lowercase
    'cargo.lock',
    'cargo.toml',
    'composer.json',
    'composer.lock',
    'go.sum',
    'go.mod',
    'go.mod.graph',
    'gopkg.lock',
    'pom.xml',
    'bom.json',
    'bcde.mvndeps',
    'build.gradle',
    '.gradle',
    'gradle.lockfile',
    'build.gradle.kts',
    '.gradle.kts',
    '.properties',
    '.kt',  # config KT files
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'deno.lock',
    'deno.json',
    'pnpm-lock.yaml',
    'npm-shrinkwrap.json',
    'packages.config',
    'project.assets.json',
    'packages.lock.json',
    'nuget.config',
    '.csproj',
    '.vbproj',
    'gemfile',
    'gemfile.lock',
    '.sbt',
    'build.scala',
    'build.sbt.lock',
    'pyproject.toml',
    'poetry.lock',
    'pipfile',
    'pipfile.lock',
    'requirements.txt',
    'setup.py',
    'mix.exs',
    'mix.lock',
    'package.swift',
    'package.resolved',
    'pubspec.yaml',
    'pubspec.lock',
    'conanfile.py',
    'conanfile.txt',
    'maven_install.json',
    'conan.lock',
)

SCA_EXCLUDED_FOLDER_IN_PATH = (
    'node_modules',
    'venv',
    '.venv',
    '__pycache__',
    '.pytest_cache',
    '.tox',
    '.mvn',
    '.gradle',
    '.npm',
    '.yarn',
    '.bundle',
    '.bloop',
    '.build',
    '.dart_tool',
    '.pub',
)

PROJECT_FILES_BY_ECOSYSTEM_MAP = {
    'crates': ['Cargo.lock', 'Cargo.toml'],
    'composer': ['composer.json', 'composer.lock'],
    'go': ['go.sum', 'go.mod', 'go.mod.graph', 'Gopkg.lock'],
    'maven_pom': ['pom.xml'],
    'maven_gradle': ['build.gradle', 'build.gradle.kts', 'gradle.lockfile'],
    'npm': [
        'package.json',
        'package-lock.json',
        'yarn.lock',
        'npm-shrinkwrap.json',
        '.npmrc',
        'pnpm-lock.yaml',
        'deno.lock',
        'deno.json',
    ],
    'nuget': ['packages.config', 'project.assets.json', 'packages.lock.json', 'nuget.config'],
    'ruby_gems': ['Gemfile', 'Gemfile.lock'],
    'sbt': ['build.sbt', 'build.scala', 'build.sbt.lock'],
    'pypi_poetry': ['pyproject.toml', 'poetry.lock'],
    'pypi_pipenv': ['Pipfile', 'Pipfile.lock'],
    'pypi_requirements': ['requirements.txt'],
    'pypi_setup': ['setup.py'],
    'hex': ['mix.exs', 'mix.lock'],
    'swift_pm': ['Package.swift', 'Package.resolved'],
    'dart': ['pubspec.yaml', 'pubspec.lock'],
    'conan': ['conanfile.py', 'conanfile.txt', 'conan.lock'],
}

COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES = [SECRET_SCAN_TYPE, SCA_SCAN_TYPE, SAST_SCAN_TYPE]

COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES = [
    PRE_COMMIT_COMMAND_SCAN_TYPE,
    PRE_COMMIT_COMMAND_SCAN_TYPE_OLD,
    PRE_RECEIVE_COMMAND_SCAN_TYPE,
    PRE_RECEIVE_COMMAND_SCAN_TYPE_OLD,
    COMMIT_HISTORY_COMMAND_SCAN_TYPE,
    COMMIT_HISTORY_COMMAND_SCAN_TYPE_OLD,
]

DEFAULT_CYCODE_DOMAIN = 'cycode.com'
DEFAULT_CYCODE_API_URL = f'https://api.{DEFAULT_CYCODE_DOMAIN}'
DEFAULT_CYCODE_APP_URL = f'https://app.{DEFAULT_CYCODE_DOMAIN}'

# env var names
CYCODE_API_URL_ENV_VAR_NAME = 'CYCODE_API_URL'
CYCODE_APP_URL_ENV_VAR_NAME = 'CYCODE_APP_URL'
TIMEOUT_ENV_VAR_NAME = 'TIMEOUT'
CYCODE_CLI_REQUEST_TIMEOUT_ENV_VAR_NAME = 'CYCODE_CLI_REQUEST_TIMEOUT'
LOGGING_LEVEL_ENV_VAR_NAME = 'LOGGING_LEVEL'
VERBOSE_ENV_VAR_NAME = 'CYCODE_CLI_VERBOSE'
DEBUG_ENV_VAR_NAME = 'CYCODE_CLI_DEBUG'

CYCODE_CONFIGURATION_DIRECTORY: str = '.cycode'

# user configuration sections names
EXCLUSIONS_BY_VALUE_SECTION_NAME = 'values'
EXCLUSIONS_BY_SHA_SECTION_NAME = 'shas'
EXCLUSIONS_BY_PATH_SECTION_NAME = 'paths'
EXCLUSIONS_BY_RULE_SECTION_NAME = 'rules'
EXCLUSIONS_BY_PACKAGE_SECTION_NAME = 'packages'
EXCLUSIONS_BY_CVE_SECTION_NAME = 'cves'

# 5MB in bytes (in decimal)
FILE_MAX_SIZE_LIMIT_IN_BYTES = 5000000

DEFAULT_ZIP_MAX_SIZE_LIMIT_IN_BYTES = 20 * 1024 * 1024
ZIP_MAX_SIZE_LIMIT_IN_BYTES = {
    SCA_SCAN_TYPE: 200 * 1024 * 1024,
    SAST_SCAN_TYPE: 50 * 1024 * 1024,
}

# scan in batches
DEFAULT_SCAN_BATCH_MAX_SIZE_IN_BYTES = 9 * 1024 * 1024
SCAN_BATCH_MAX_SIZE_IN_BYTES = {SAST_SCAN_TYPE: 50 * 1024 * 1024}
SCAN_BATCH_MAX_SIZE_IN_BYTES_ENV_VAR_NAME = 'SCAN_BATCH_MAX_SIZE_IN_BYTES'

DEFAULT_SCAN_BATCH_MAX_FILES_COUNT = 1000
SCAN_BATCH_MAX_FILES_COUNT_ENV_VAR_NAME = 'SCAN_BATCH_MAX_FILES_COUNT'

# if we increase this values, the server doesn't allow connecting (ConnectionError)
SCAN_BATCH_MAX_PARALLEL_SCANS = 5
SCAN_BATCH_SCANS_PER_CPU = 1

# sentry
SENTRY_DSN = 'https://5e26b304b30ced3a34394b6f81f1076d@o1026942.ingest.us.sentry.io/4507543840096256'
SENTRY_DEBUG = False
SENTRY_SAMPLE_RATE = 1.0
SENTRY_SEND_DEFAULT_PII = False
SENTRY_INCLUDE_LOCAL_VARIABLES = False
SENTRY_MAX_REQUEST_BODY_SIZE = 'never'

# sync scans
SYNC_SCAN_TIMEOUT_IN_SECONDS_ENV_VAR_NAME = 'SYNC_SCAN_TIMEOUT_IN_SECONDS'
DEFAULT_SYNC_SCAN_TIMEOUT_IN_SECONDS = 180

# ai remediation
AI_REMEDIATION_TIMEOUT_IN_SECONDS_ENV_VAR_NAME = 'AI_REMEDIATION_TIMEOUT_IN_SECONDS'
DEFAULT_AI_REMEDIATION_TIMEOUT_IN_SECONDS = 60

# report with polling
REPORT_POLLING_WAIT_INTERVAL_IN_SECONDS = 5
DEFAULT_REPORT_POLLING_TIMEOUT_IN_SECONDS = 600
REPORT_POLLING_TIMEOUT_IN_SECONDS_ENV_VAR_NAME = 'REPORT_POLLING_TIMEOUT_IN_SECONDS'

# scan with polling
SCAN_POLLING_WAIT_INTERVAL_IN_SECONDS = 5
DEFAULT_SCAN_POLLING_TIMEOUT_IN_SECONDS = 3600
SCAN_POLLING_TIMEOUT_IN_SECONDS_ENV_VAR_NAME = 'SCAN_POLLING_TIMEOUT_IN_SECONDS'
DEFAULT_SCA_PRE_COMMIT_TIMEOUT_IN_SECONDS = 600
SCA_PRE_COMMIT_TIMEOUT_IN_SECONDS_ENV_VAR_NAME = 'SCA_PRE_COMMIT_TIMEOUT_IN_SECONDS'

# pre receive scan
PRE_RECEIVE_MAX_COMMITS_TO_SCAN_COUNT_ENV_VAR_NAME = 'PRE_RECEIVE_MAX_COMMITS_TO_SCAN_COUNT'
DEFAULT_PRE_RECEIVE_MAX_COMMITS_TO_SCAN_COUNT = 50
PRE_RECEIVE_COMMAND_TIMEOUT_ENV_VAR_NAME = 'PRE_RECEIVE_COMMAND_TIMEOUT'
DEFAULT_PRE_RECEIVE_COMMAND_TIMEOUT_IN_SECONDS = 60
PRE_RECEIVE_REMEDIATION_MESSAGE = """
Cycode Secrets Push Protection
------------------------------------------------------------------------------
Resolve the following secrets by rewriting your local commit history before pushing again.
Learn how to: https://cycode.com/dont-let-hardcoded-secrets-compromise-your-security-4-effective-remediation-techniques
"""

EXCLUDE_DETECTIONS_IN_DELETED_LINES_ENV_VAR_NAME = 'EXCLUDE_DETECTIONS_IN_DELETED_LINES'
DEFAULT_EXCLUDE_DETECTIONS_IN_DELETED_LINES = True

# report statuses
REPORT_STATUS_COMPLETED = 'Completed'
REPORT_STATUS_ERROR = 'Failed'

# scan statuses
SCAN_STATUS_COMPLETED = 'Completed'
SCAN_STATUS_ERROR = 'Error'

# git consts
COMMIT_DIFF_DELETED_FILE_CHANGE_TYPE = 'D'
GIT_HEAD_COMMIT_REV = 'HEAD'
GIT_EMPTY_TREE_OBJECT = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
EMPTY_COMMIT_SHA = '0000000000000000000000000000000000000000'
GIT_PUSH_OPTION_COUNT_ENV_VAR_NAME = 'GIT_PUSH_OPTION_COUNT'
GIT_PUSH_OPTION_ENV_VAR_PREFIX = 'GIT_PUSH_OPTION_'

SKIP_SCAN_FLAG = 'skip-cycode-scan'
VERBOSE_SCAN_FLAG = 'verbose'

ISSUE_DETECTED_STATUS_CODE = 1
NO_ISSUES_STATUS_CODE = 0

LICENSE_COMPLIANCE_POLICY_ID = '8f681450-49e1-4f7e-85b7-0c8fe84b3a35'
PACKAGE_VULNERABILITY_POLICY_ID = '9369d10a-9ac0-48d3-9921-5de7fe9a37a7'

# Shortcut dependency paths by remove all middle dependencies
# between direct dependency and influence/vulnerable dependency.
# Example: A -> B -> C
# Result: A -> ... -> C
SCA_SHORTCUT_DEPENDENCY_PATHS = 2

PLASTIC_VCS_DATA_SEPARATOR = ':::'
PLASTIC_VSC_CLI_TIMEOUT = 10
PLASTIC_VCS_REMOTE_URI_PREFIX = 'plastic::'
