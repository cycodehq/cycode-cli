import pytest

from cycode.cli import consts
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.files_collector.zip_documents import _validate_zip_file_size
from cycode.cli.utils.scan_utils import should_use_presigned_upload


def test_sast_always_uses_presigned_upload() -> None:
    assert should_use_presigned_upload(consts.SAST_SCAN_TYPE) is True


def test_secret_does_not_use_presigned_upload_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(consts.SECRET_SCAN_ASYNC_ENV_VAR_NAME, raising=False)
    assert should_use_presigned_upload(consts.SECRET_SCAN_TYPE) is False


@pytest.mark.parametrize('env_value', ['true', 'True', '1', 'yes', 'y', 'on', 'enabled'])
def test_secret_uses_presigned_upload_when_env_enabled(monkeypatch: pytest.MonkeyPatch, env_value: str) -> None:
    monkeypatch.setenv(consts.SECRET_SCAN_ASYNC_ENV_VAR_NAME, env_value)
    assert should_use_presigned_upload(consts.SECRET_SCAN_TYPE) is True


@pytest.mark.parametrize('env_value', ['false', '0', 'no', '', 'off'])
def test_secret_ignores_non_truthy_env_values(monkeypatch: pytest.MonkeyPatch, env_value: str) -> None:
    monkeypatch.setenv(consts.SECRET_SCAN_ASYNC_ENV_VAR_NAME, env_value)
    assert should_use_presigned_upload(consts.SECRET_SCAN_TYPE) is False


def test_sca_never_uses_presigned_upload() -> None:
    assert should_use_presigned_upload(consts.SCA_SCAN_TYPE) is False


def test_secret_zip_size_limit_uses_default_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(consts.SECRET_SCAN_ASYNC_ENV_VAR_NAME, raising=False)
    # A zip just above the default 20 MB limit must be rejected on the previous (batched) flow.
    with pytest.raises(custom_exceptions.ZipTooLargeError):
        _validate_zip_file_size(consts.SECRET_SCAN_TYPE, consts.DEFAULT_ZIP_MAX_SIZE_LIMIT_IN_BYTES + 1)


def test_secret_zip_size_limit_uses_presigned_limit_when_env_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(consts.SECRET_SCAN_ASYNC_ENV_VAR_NAME, 'true')
    # The same zip fits under the 5 GB presigned limit when async is enabled.
    _validate_zip_file_size(consts.SECRET_SCAN_TYPE, consts.DEFAULT_ZIP_MAX_SIZE_LIMIT_IN_BYTES + 1)
    with pytest.raises(custom_exceptions.ZipTooLargeError):
        _validate_zip_file_size(
            consts.SECRET_SCAN_TYPE, consts.PRESIGNED_LINK_UPLOADED_ZIP_MAX_SIZE_LIMIT_IN_BYTES + 1
        )
