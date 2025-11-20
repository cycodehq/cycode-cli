import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import responses
from typer.testing import CliRunner

from cycode.cli.app import app
from cycode.cli.cli_types import BusinessImpactOption
from cycode.cyclient.client_creator import create_import_sbom_client
from cycode.cyclient.import_sbom_client import ImportSbomClient, ImportSbomParameters
from tests.conftest import _CLIENT_ID, _CLIENT_SECRET, CLI_ENV_VARS
from tests.cyclient.mocked_responses import import_sbom_client as mocked_import_sbom

if TYPE_CHECKING:
    from pytest_mock import MockerFixture


@pytest.fixture(scope='session')
def import_sbom_client() -> ImportSbomClient:
    return create_import_sbom_client(_CLIENT_ID, _CLIENT_SECRET, False)


def _validate_called_endpoint(calls: responses.CallList, path: str, expected_count: int = 1) -> None:
    # Verify the import request was made
    import_calls = [c for c in calls if path in c.request.url]
    assert len(import_calls) == expected_count


class TestImportSbomParameters:
    """Tests for ImportSbomParameters.to_request_form() method"""

    def test_to_request_form_with_all_fields(self) -> None:
        data = {
            'Name': 'test-sbom',
            'Vendor': 'test-vendor',
            'BusinessImpact': BusinessImpactOption.HIGH,
            'Labels': ['label1', 'label2'],
            'Owners': ['owner1-id', 'owner2-id'],
        }

        params = ImportSbomParameters(**data)
        form_data = params.to_request_form()

        for key, val in data.items():
            if isinstance(val, list):
                assert form_data[f'{key}[]'] == val
            else:
                assert form_data[key] == val

    def test_to_request_form_with_required_fields_only(self) -> None:
        params = ImportSbomParameters(
            Name='test-sbom',
            Vendor='test-vendor',
            BusinessImpact=BusinessImpactOption.MEDIUM,
            Labels=[],
            Owners=[],
        )
        form_data = params.to_request_form()

        # Assert
        assert form_data['Name'] == 'test-sbom'
        assert form_data['Vendor'] == 'test-vendor'
        assert form_data['BusinessImpact'] == BusinessImpactOption.MEDIUM
        assert 'Labels[]' not in form_data
        assert 'Owners[]' not in form_data


class TestSbomCommand:
    """Tests for sbom_command with CLI integration"""

    @responses.activate
    def test_sbom_command_happy_path(
        self,
        mocker: 'MockerFixture',
        api_token_response: responses.Response,
        import_sbom_client: ImportSbomClient,
    ) -> None:
        responses.add(api_token_response)
        mocked_import_sbom.mock_import_sbom_responses(responses, import_sbom_client)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file.write('{"sbom": "content"}')
            temp_file_path = temp_file.name

        try:
            args = [
                'import',
                'sbom',
                '--name',
                'test-sbom',
                '--vendor',
                'test-vendor',
                temp_file_path,
            ]
            result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

            assert result.exit_code == 0
            _validate_called_endpoint(responses.calls, ImportSbomClient.IMPORT_SBOM_REQUEST_PATH)

        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    @responses.activate
    def test_sbom_command_with_all_options(
        self,
        mocker: 'MockerFixture',
        api_token_response: responses.Response,
        import_sbom_client: ImportSbomClient,
    ) -> None:
        responses.add(api_token_response)
        mocked_import_sbom.mock_member_details_response(responses, import_sbom_client, 'user1@example.com', 'user-123')
        mocked_import_sbom.mock_import_sbom_responses(responses, import_sbom_client)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file.write('{"sbom": "content"}')
            temp_file_path = temp_file.name

        try:
            args = [
                'import',
                'sbom',
                '--name',
                'test-sbom',
                '--vendor',
                'test-vendor',
                '--label',
                'production',
                '--label',
                'critical',
                '--owner',
                'user1@example.com',
                '--business-impact',
                'High',
                temp_file_path,
            ]
            result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

            # Assert
            assert result.exit_code == 0
            _validate_called_endpoint(responses.calls, ImportSbomClient.IMPORT_SBOM_REQUEST_PATH)
            _validate_called_endpoint(responses.calls, ImportSbomClient.GET_USER_ID_REQUEST_PATH)

        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_sbom_command_file_not_exists(self, mocker: 'MockerFixture') -> None:
        from uuid import uuid4

        non_existent_file = str(uuid4())

        args = [
            'import',
            'sbom',
            '--name',
            'test-sbom',
            '--vendor',
            'test-vendor',
            non_existent_file,
        ]
        result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

        assert result.exit_code != 0
        assert "Invalid value for 'PATH': File " in result.output
        assert 'not exist' in result.output

    def test_sbom_command_file_is_directory(self, mocker: 'MockerFixture') -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            args = [
                'import',
                'sbom',
                '--name',
                'test-sbom',
                '--vendor',
                'test-vendor',
                temp_dir,
            ]
            result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

            # Typer should reject this before the command runs
            assert result.exit_code != 0
            # The error message contains "is a" and "directory" (may be across lines)
            assert 'directory' in result.output.lower()

    @responses.activate
    def test_sbom_command_invalid_owner_email(
        self,
        mocker: 'MockerFixture',
        api_token_response: responses.Response,
        import_sbom_client: ImportSbomClient,
    ) -> None:
        responses.add(api_token_response)
        # Mock with no external_id to simulate user not found
        mocked_import_sbom.mock_member_details_response(responses, import_sbom_client, 'invalid@example.com', None)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file.write('{"sbom": "content"}')
            temp_file_path = temp_file.name

        try:
            args = [
                'import',
                'sbom',
                '--name',
                'test-sbom',
                '--vendor',
                'test-vendor',
                '--owner',
                'invalid@example.com',
                temp_file_path,
            ]
            result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

            assert result.exit_code == 1
            assert 'invalid@example.com' in result.output
            assert 'Failed to find user' in result.output or 'not found' in result.output.lower()
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    @responses.activate
    def test_sbom_command_http_400_error(
        self,
        mocker: 'MockerFixture',
        api_token_response: responses.Response,
        import_sbom_client: ImportSbomClient,
    ) -> None:
        responses.add(api_token_response)
        # Mock the SBOM import API endpoint to return 400
        mocked_import_sbom.mock_import_sbom_responses(responses, import_sbom_client, status=400)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file.write('{"sbom": "content"}')
            temp_file_path = temp_file.name

        try:
            args = [
                'import',
                'sbom',
                '--name',
                'test-sbom',
                '--vendor',
                'test-vendor',
                temp_file_path,
            ]
            result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

            # HTTP 400 errors are also soft failures - exit with code 0
            assert result.exit_code == 0
            _validate_called_endpoint(responses.calls, ImportSbomClient.IMPORT_SBOM_REQUEST_PATH)
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    @responses.activate
    def test_sbom_command_http_500_error(
        self,
        mocker: 'MockerFixture',
        api_token_response: responses.Response,
        import_sbom_client: ImportSbomClient,
    ) -> None:
        responses.add(api_token_response)
        # Mock the SBOM import API endpoint to return 500 (soft failure)
        mocked_import_sbom.mock_import_sbom_responses(responses, import_sbom_client, status=500)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file.write('{"sbom": "content"}')
            temp_file_path = temp_file.name

        try:
            args = [
                'import',
                'sbom',
                '--name',
                'test-sbom',
                '--vendor',
                'test-vendor',
                temp_file_path,
            ]
            result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

            assert result.exit_code == 0
            _validate_called_endpoint(responses.calls, ImportSbomClient.IMPORT_SBOM_REQUEST_PATH)
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    @responses.activate
    def test_sbom_command_multiple_owners(
        self,
        mocker: 'MockerFixture',
        api_token_response: responses.Response,
        import_sbom_client: ImportSbomClient,
    ) -> None:
        username1 = 'user1'
        username2 = 'user2'

        responses.add(api_token_response)
        mocked_import_sbom.mock_import_sbom_responses(responses, import_sbom_client)
        mocked_import_sbom.mock_member_details_response(
            responses, import_sbom_client, f'{username1}@example.com', 'user-123'
        )
        mocked_import_sbom.mock_member_details_response(
            responses, import_sbom_client, f'{username2}@example.com', 'user-456'
        )

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file.write('{"sbom": "content"}')
            temp_file_path = temp_file.name

        try:
            args = [
                'import',
                'sbom',
                '--name',
                'test-sbom',
                '--vendor',
                'test-vendor',
                '--owner',
                f'{username1}@example.com',
                '--owner',
                f'{username2}@example.com',
                temp_file_path,
            ]
            result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

            assert result.exit_code == 0
            _validate_called_endpoint(responses.calls, ImportSbomClient.IMPORT_SBOM_REQUEST_PATH)
            _validate_called_endpoint(responses.calls, ImportSbomClient.GET_USER_ID_REQUEST_PATH, 2)
        finally:
            Path(temp_file_path).unlink(missing_ok=True)
