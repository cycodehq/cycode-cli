import json
from dataclasses import asdict, dataclass


class CliStatusBase:
    def as_dict(self) -> dict[str, any]:
        return asdict(self)

    def _get_text_message_part(self, key: str, value: any, intent: int = 0) -> str:
        message_parts = []

        intent_prefix = ' ' * intent * 2
        human_readable_key = key.replace('_', ' ').capitalize()

        if isinstance(value, dict):
            message_parts.append(f'{intent_prefix}{human_readable_key}:')
            for sub_key, sub_value in value.items():
                message_parts.append(self._get_text_message_part(sub_key, sub_value, intent=intent + 1))
        elif isinstance(value, (list, set, tuple)):
            message_parts.append(f'{intent_prefix}{human_readable_key}:')
            for index, sub_value in enumerate(value):
                message_parts.append(self._get_text_message_part(f'#{index}', sub_value, intent=intent + 1))
        else:
            message_parts.append(f'{intent_prefix}{human_readable_key}: {value}')

        return '\n'.join(message_parts)

    def as_text(self) -> str:
        message_parts = []
        for key, value in self.as_dict().items():
            message_parts.append(self._get_text_message_part(key, value))

        return '\n'.join(message_parts)

    def as_json(self) -> str:
        return json.dumps(self.as_dict())


@dataclass
class CliSupportedModulesStatus(CliStatusBase):
    secret_scanning: bool = False
    sca_scanning: bool = False
    iac_scanning: bool = False
    sast_scanning: bool = False
    ai_large_language_model: bool = False


@dataclass
class CliStatus(CliStatusBase):
    program: str
    version: str
    os: str
    arch: str
    python_version: str
    installation_id: str
    app_url: str
    api_url: str
    is_authenticated: bool
    user_id: str = None
    tenant_id: str = None
    supported_modules: CliSupportedModulesStatus = None
