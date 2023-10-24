PROGRAM_NAME = 'cycode'
CLI_CONTEXT_SETTINGS = {
    'terminal_width': 10**9,
    'max_content_width': 10**9,
}

PRE_COMMIT_COMMAND_SCAN_TYPE = 'pre_commit'
PRE_RECEIVE_COMMAND_SCAN_TYPE = 'pre_receive'
COMMIT_HISTORY_COMMAND_SCAN_TYPE = 'commit_history'

SECRET_SCAN_TYPE = 'secret'  # noqa: S105
INFRA_CONFIGURATION_SCAN_TYPE = 'iac'
SCA_SCAN_TYPE = 'sca'
SAST_SCAN_TYPE = 'sast'

INFRA_CONFIGURATION_SCAN_SUPPORTED_FILES = ('.tf', '.tf.json', '.json', '.yaml', '.yml', 'dockerfile')

SECRET_SCAN_FILE_EXTENSIONS_TO_IGNORE = (
    '.7z',
    '.bmp',
    '.bz2',
    '.dmg',
    '.exe',
    '.gif',
    '.gz',
    '.ico',
    '.jar',
    '.jpg',
    '.jpeg',
    '.png',
    '.rar',
    '.realm',
    '.s7z',
    '.svg',
    '.tar',
    '.tif',
    '.tiff',
    '.webp',
    '.zi',
    '.lock',
    '.css',
    '.less',
    '.dll',
    '.enc',
    '.deb',
    '.obj',
    '.model',
)

SCA_CONFIGURATION_SCAN_SUPPORTED_FILES = (
    'cargo.lock',
    'cargo.toml',
    'composer.json',
    'composer.lock',
    'go.sum',
    'go.mod',
    'gopkg.lock',
    'pom.xml',
    'build.gradle',
    'gradle.lockfile',
    'build.gradle.kts',
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'npm-shrinkwrap.json',
    'packages.config',
    'project.assets.json',
    'packages.lock.json',
    'nuget.config',
    '.csproj',
    'gemfile',
    'gemfile.lock',
    'build.sbt',
    'build.scala',
    'build.sbt.lock',
    'pyproject.toml',
    'poetry.lock',
    'pipfile',
    'pipfile.lock',
    'requirements.txt',
    'setup.py',
)

SCA_EXCLUDED_PATHS = ('node_modules',)

PROJECT_FILES_BY_ECOSYSTEM_MAP = {
    'crates': ['Cargo.lock', 'Cargo.toml'],
    'composer': ['composer.json', 'composer.lock'],
    'go': ['go.sum', 'go.mod', 'Gopkg.lock'],
    'maven_pom': ['pom.xml'],
    'maven_gradle': ['build.gradle', 'build.gradle.kts', 'gradle.lockfile'],
    'npm': ['package.json', 'package-lock.json', 'yarn.lock', 'npm-shrinkwrap.json', '.npmrc'],
    'nuget': ['packages.config', 'project.assets.json', 'packages.lock.json', 'nuget.config'],
    'ruby_gems': ['Gemfile', 'Gemfile.lock'],
    'sbt': ['build.sbt', 'build.scala', 'build.sbt.lock'],
    'pypi_poetry': ['pyproject.toml', 'poetry.lock'],
    'pypi_pipenv': ['Pipfile', 'Pipfile.lock'],
    'pypi_requirements': ['requirements.txt'],
    'pypi_setup': ['setup.py'],
}

COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES = [SECRET_SCAN_TYPE, SCA_SCAN_TYPE]

COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES = [PRE_RECEIVE_COMMAND_SCAN_TYPE, COMMIT_HISTORY_COMMAND_SCAN_TYPE]

DEFAULT_CYCODE_API_URL = 'https://api.cycode.com'
DEFAULT_CYCODE_APP_URL = 'https://app.cycode.com'

# env var names
CYCODE_API_URL_ENV_VAR_NAME = 'CYCODE_API_URL'
CYCODE_APP_URL_ENV_VAR_NAME = 'CYCODE_APP_URL'
TIMEOUT_ENV_VAR_NAME = 'TIMEOUT'
CYCODE_CLI_REQUEST_TIMEOUT_ENV_VAR_NAME = 'CYCODE_CLI_REQUEST_TIMEOUT'
LOGGING_LEVEL_ENV_VAR_NAME = 'LOGGING_LEVEL'
VERBOSE_ENV_VAR_NAME = 'CYCODE_CLI_VERBOSE'

CYCODE_CONFIGURATION_DIRECTORY: str = '.cycode'

# user configuration sections names
EXCLUSIONS_BY_VALUE_SECTION_NAME = 'values'
EXCLUSIONS_BY_SHA_SECTION_NAME = 'shas'
EXCLUSIONS_BY_PATH_SECTION_NAME = 'paths'
EXCLUSIONS_BY_RULE_SECTION_NAME = 'rules'
EXCLUSIONS_BY_PACKAGE_SECTION_NAME = 'packages'

# 1MB in bytes (in decimal)
FILE_MAX_SIZE_LIMIT_IN_BYTES = 1000000

# 20MB in bytes (in binary)
ZIP_MAX_SIZE_LIMIT_IN_BYTES = 20971520
# 200MB in bytes (in binary)
SCA_ZIP_MAX_SIZE_LIMIT_IN_BYTES = 209715200

# scan in batches
SCAN_BATCH_MAX_SIZE_IN_BYTES = 9 * 1024 * 1024
SCAN_BATCH_MAX_FILES_COUNT = 1000
# if we increase this values, the server doesn't allow connecting (ConnectionError)
SCAN_BATCH_MAX_PARALLEL_SCANS = 5
SCAN_BATCH_SCANS_PER_CPU = 1

# report with polling
REPORT_POLLING_WAIT_INTERVAL_IN_SECONDS = 5
DEFAULT_REPORT_POLLING_TIMEOUT_IN_SECONDS = 600
REPORT_POLLING_TIMEOUT_IN_SECONDS_ENV_VAR_NAME = 'REPORT_POLLING_TIMEOUT_IN_SECONDS'

# scan with polling
SCAN_POLLING_WAIT_INTERVAL_IN_SECONDS = 5
DEFAULT_SCAN_POLLING_TIMEOUT_IN_SECONDS = 3600
SCAN_POLLING_TIMEOUT_IN_SECONDS_ENV_VAR_NAME = 'SCAN_POLLING_TIMEOUT_IN_SECONDS'
DETECTIONS_COUNT_VERIFICATION_TIMEOUT_IN_SECONDS = 600
DETECTIONS_COUNT_VERIFICATION_WAIT_INTERVAL_IN_SECONDS = 10
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

SCA_SKIP_RESTORE_DEPENDENCIES_FLAG = 'no-restore'
