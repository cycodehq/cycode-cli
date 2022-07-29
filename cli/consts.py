
PRE_COMMIT_SCAN_COMMAND_TYPE = 'pre_commit'

SECRET_SCAN_TYPE = 'secret'
INFRA_CONFIGURATION_SCAN_TYPE = 'iac'

INFRA_CONFIGURATION_SCAN_SUPPORTED_FILES = [
    '.tf', '.tf.json', '.json', '.yaml', '.yml', 'dockerfile'
]

SECRET_SCAN_FILE_EXTENSIONS_TO_IGNORE = [
    '.7z', '.bmp', '.bz2', '.dmg', '.exe', '.gif', '.gz', '.ico', '.jar', '.jpg', '.jpeg', '.png', '.rar',
    '.realm', '.s7z', '.svg', '.tar', '.tif', '.tiff', '.webp', '.zi', '.lock', '.css', '.less', '.dll',
    '.enc', '.deb', '.obj', '.model'
]

DEFAULT_CYCODE_API_URL = "https://api.cycode.com"

# env var names
CYCODE_API_URL_VAR_NAME = "CYCODE_API_URL"
TIMEOUT_ENV_VAR_NAME = "TIMEOUT"
LOGGING_LEVEL_ENV_VAR_NAME = "LOGGING_LEVEL"
# use only for dev envs locally
DEV_MODE_ENV_VAR_NAME = "DEV_MODE"
BATCH_SIZE_ENV_VAR_NAME = "BATCH_SIZE"
VERBOSE_ENV_VAR_NAME = "CYCODE_CLI_VERBOSE"

CYCODE_CONFIGURATION_DIRECTORY: str = '.cycode'

# user configuration sections names
EXCLUSIONS_BY_VALUE_SECTION_NAME = 'values'
EXCLUSIONS_BY_SHA_SECTION_NAME = 'shas'
EXCLUSIONS_BY_PATH_SECTION_NAME = 'paths'
EXCLUSIONS_BY_RULE_SECTION_NAME = 'rules'


# 1MB in bytes (in decimal)
FILE_MAX_SIZE_LIMIT_IN_BYTES = 1000000

# 10MB in bytes (in binary)
ZIP_MAX_SIZE_LIMIT_IN_BYTES = 10485760
