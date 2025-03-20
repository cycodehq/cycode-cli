from enum import Enum

from cycode.cli import consts


class OutputTypeOption(str, Enum):
    TEXT = 'text'
    JSON = 'json'
    TABLE = 'table'


class ScanTypeOption(str, Enum):
    SECRET = consts.SECRET_SCAN_TYPE
    SCA = consts.SCA_SCAN_TYPE
    IAC = consts.IAC_SCAN_TYPE
    SAST = consts.SAST_SCAN_TYPE


class ScaScanTypeOption(str, Enum):
    PACKAGE_VULNERABILITIES = 'package-vulnerabilities'
    LICENSE_COMPLIANCE = 'license-compliance'


class SbomFormatOption(str, Enum):
    SPDX_2_2 = 'spdx-2.2'
    SPDX_2_3 = 'spdx-2.3'
    CYCLONEDX_1_4 = 'cyclonedx-1.4'


class SbomOutputFormatOption(str, Enum):
    JSON = 'json'


class SeverityOption(str, Enum):
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

    @staticmethod
    def get_member_weight(name: str) -> int:
        return _SEVERITY_WEIGHTS.get(name.lower(), _SEVERITY_DEFAULT_WEIGHT)

    @staticmethod
    def get_member_color(name: str) -> str:
        return _SEVERITY_COLORS.get(name.lower(), _SEVERITY_DEFAULT_COLOR)


_SEVERITY_DEFAULT_WEIGHT = -1
_SEVERITY_WEIGHTS = {
    SeverityOption.INFO.value: 0,
    SeverityOption.LOW.value: 1,
    SeverityOption.MEDIUM.value: 2,
    SeverityOption.HIGH.value: 3,
    SeverityOption.CRITICAL.value: 4,
}

_SEVERITY_DEFAULT_COLOR = 'white'
_SEVERITY_COLORS = {
    SeverityOption.INFO.value: 'deep_sky_blue1',
    SeverityOption.LOW.value: 'gold1',
    SeverityOption.MEDIUM.value: 'dark_orange',
    SeverityOption.HIGH.value: 'red1',
    SeverityOption.CRITICAL.value: 'red3',
}
