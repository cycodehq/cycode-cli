import os
from pathlib import Path
from cli.utils.yaml_utils import read_file
from cli.config import CYCODE_CLIENT_ID_ENV_VAR_NAME, CYCODE_CLIENT_SECRET_ENV_VAR_NAME
from cli.user_settings.base_file_manager import BaseFileManager


class CredentialsManager(BaseFileManager):

    HOME_PATH: str = Path.home()
    CYCODE_HIDDEN_DIRECTORY: str = '.cycode'
    FILE_NAME: str = 'credentials.yaml'
    CLIENT_ID_FIELD_NAME: str = 'cycode_client_id'
    CLIENT_SECRET_FIELD_NAME: str = 'cycode_client_secret'

    def get_credentials(self) -> (str, str):
        client_id, client_secret = self.get_credentials_from_environment_variables()
        if client_id is not None and client_secret is not None:
            return client_id, client_secret

        return self.get_credentials_from_file()

    def get_credentials_from_environment_variables(self) -> (str, str):
        client_id = os.getenv(CYCODE_CLIENT_ID_ENV_VAR_NAME)
        client_secret = os.getenv(CYCODE_CLIENT_SECRET_ENV_VAR_NAME)
        return client_id, client_secret

    def get_credentials_from_file(self) -> (str, str):
        credentials_filename = self.get_filename()
        try:
            file_content = read_file(credentials_filename)
        except FileNotFoundError:
            return None, None

        client_id = file_content.get(self.CLIENT_ID_FIELD_NAME)
        client_secret = file_content.get(self.CLIENT_SECRET_FIELD_NAME)
        return client_id, client_secret

    def update_credentials_file(self, client_id: str, client_secret: str):
        credentials = {
            self.CLIENT_ID_FIELD_NAME: client_id,
            self.CLIENT_SECRET_FIELD_NAME: client_secret
        }

        filename = self.get_filename()
        self.write_content_to_file(credentials)

    def get_filename(self) -> str:
        return os.path.join(self.HOME_PATH, self.CYCODE_HIDDEN_DIRECTORY, self.FILE_NAME)
