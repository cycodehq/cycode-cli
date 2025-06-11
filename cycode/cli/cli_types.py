from enum import Enum

from cycode.cli import consts


class StrEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class McpTransportOption(StrEnum):
    STDIO = 'stdio'
    SSE = 'sse'
    STREAMABLE_HTTP = 'streamable-http'


class OutputTypeOption(StrEnum):
    RICH = 'rich'
    TEXT = 'text'
    JSON = 'json'
    TABLE = 'table'


class ExportTypeOption(StrEnum):
    JSON = 'json'
    HTML = 'html'
    SVG = 'svg'


class ScanTypeOption(StrEnum):
    SECRET = consts.SECRET_SCAN_TYPE
    SCA = consts.SCA_SCAN_TYPE
    IAC = consts.IAC_SCAN_TYPE
    SAST = consts.SAST_SCAN_TYPE

    def __str__(self) -> str:
        return self.value


class ScaScanTypeOption(StrEnum):
    PACKAGE_VULNERABILITIES = 'package-vulnerabilities'
    LICENSE_COMPLIANCE = 'license-compliance'


class SbomFormatOption(StrEnum):
    SPDX_2_2 = 'spdx-2.2'
    SPDX_2_3 = 'spdx-2.3'
    CYCLONEDX_1_4 = 'cyclonedx-1.4'


class SbomOutputFormatOption(StrEnum):
    JSON = 'json'


class SeverityOption(StrEnum):
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

    @classmethod
    def _missing_(cls, value: str) -> str:
        value = value.lower()
        for member in cls:
            if member.lower() == value:
                return member

        return cls.INFO  # fallback to INFO if no match is found

    @staticmethod
    def get_member_weight(name: str) -> int:
        return _SEVERITY_WEIGHTS.get(name.lower(), _SEVERITY_DEFAULT_WEIGHT)

    @staticmethod
    def get_member_color(name: str) -> str:
        return _SEVERITY_COLORS.get(name.lower(), _SEVERITY_DEFAULT_COLOR)

    @staticmethod
    def get_member_emoji(name: str) -> str:
        return _SEVERITY_EMOJIS.get(name.lower(), _SEVERITY_DEFAULT_EMOJI)

    def __rich__(self) -> str:
        color = self.get_member_color(self.value)
        return f'[{color}]{self.value.upper()}[/]'


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

_SEVERITY_DEFAULT_EMOJI = ':white_circle:'
_SEVERITY_EMOJIS = {
    SeverityOption.INFO.value: ':blue_circle:',
    SeverityOption.LOW.value: ':yellow_circle:',
    SeverityOption.MEDIUM.value: ':orange_circle:',
    SeverityOption.HIGH.value: ':red_circle:',
    SeverityOption.CRITICAL.value: ':exclamation_mark:',  # double_exclamation_mark is not red
}
