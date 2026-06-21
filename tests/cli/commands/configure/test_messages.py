from typing import TYPE_CHECKING

from cycode.cli.apps.configure import messages
from cycode.cli.config import CYCODE_CLIENT_ID_ENV_VAR_NAME, CYCODE_CLIENT_SECRET_ENV_VAR_NAME

if TYPE_CHECKING:
    import pytest


def test_credentials_override_warning_absent_when_no_env_vars(monkeypatch: 'pytest.MonkeyPatch') -> None:
    monkeypatch.delenv(CYCODE_CLIENT_ID_ENV_VAR_NAME, raising=False)
    monkeypatch.delenv(CYCODE_CLIENT_SECRET_ENV_VAR_NAME, raising=False)

    assert messages.get_credentials_environment_variables_override_warning() is None


def test_credentials_override_warning_present_when_only_client_id_set(monkeypatch: 'pytest.MonkeyPatch') -> None:
    monkeypatch.setenv(CYCODE_CLIENT_ID_ENV_VAR_NAME, 'env-client-id')
    monkeypatch.delenv(CYCODE_CLIENT_SECRET_ENV_VAR_NAME, raising=False)

    assert messages.get_credentials_environment_variables_override_warning() is not None


def test_credentials_success_message_does_not_embed_override_warning(monkeypatch: 'pytest.MonkeyPatch') -> None:
    monkeypatch.setenv(CYCODE_CLIENT_ID_ENV_VAR_NAME, 'env-client-id')
    monkeypatch.setenv(CYCODE_CLIENT_SECRET_ENV_VAR_NAME, 'env-client-secret')

    assert 'environment variables' not in messages.get_credentials_update_result_message()
