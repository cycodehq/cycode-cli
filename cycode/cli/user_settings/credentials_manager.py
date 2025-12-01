import os
from pathlib import Path
from typing import Optional

from cycode.cli.config import (
    CYCODE_CLIENT_ID_ENV_VAR_NAME,
    CYCODE_CLIENT_SECRET_ENV_VAR_NAME,
    CYCODE_ID_TOKEN_ENV_VAR_NAME,
)
from cycode.cli.user_settings.base_file_manager import BaseFileManager
from cycode.cli.user_settings.jwt_creator import JwtCreator
from cycode.cli.utils.sentry import setup_scope_from_access_token


class CredentialsManager(BaseFileManager):
    HOME_PATH: str = Path.home()
    CYCODE_HIDDEN_DIRECTORY: str = '.cycode'
    FILE_NAME: str = 'credentials.yaml'

    CLIENT_ID_FIELD_NAME: str = 'cycode_client_id'
    CLIENT_SECRET_FIELD_NAME: str = 'cycode_client_secret'
    ID_TOKEN_FIELD_NAME: str = 'cycode_id_token'
    ACCESS_TOKEN_FIELD_NAME: str = 'cycode_access_token'
    ACCESS_TOKEN_EXPIRES_IN_FIELD_NAME: str = 'cycode_access_token_expires_in'
    ACCESS_TOKEN_CREATOR_FIELD_NAME: str = 'cycode_access_token_creator'

    def get_credentials(self) -> tuple[str, str]:
        client_id, client_secret = self.get_credentials_from_environment_variables()
        if client_id is not None and client_secret is not None:
            return client_id, client_secret

        return self.get_credentials_from_file()

    @staticmethod
    def get_credentials_from_environment_variables() -> tuple[str, str]:
        client_id = os.getenv(CYCODE_CLIENT_ID_ENV_VAR_NAME)
        client_secret = os.getenv(CYCODE_CLIENT_SECRET_ENV_VAR_NAME)
        return client_id, client_secret

    def get_credentials_from_file(self) -> tuple[Optional[str], Optional[str]]:
        file_content = self.read_file()
        client_id = file_content.get(self.CLIENT_ID_FIELD_NAME)
        client_secret = file_content.get(self.CLIENT_SECRET_FIELD_NAME)
        return client_id, client_secret

    def get_oidc_credentials_from_file(self) -> tuple[Optional[str], Optional[str]]:
        file_content = self.read_file()
        client_id = file_content.get(self.CLIENT_ID_FIELD_NAME)
        id_token = file_content.get(self.ID_TOKEN_FIELD_NAME)
        return client_id, id_token

    def get_oidc_credentials(self) -> tuple[Optional[str], Optional[str]]:
        client_id = os.getenv(CYCODE_CLIENT_ID_ENV_VAR_NAME)
        id_token = os.getenv(CYCODE_ID_TOKEN_ENV_VAR_NAME)

        if client_id is not None and id_token is not None:
            return client_id, id_token

        return self.get_oidc_credentials_from_file()

    def update_oidc_credentials(self, client_id: str, id_token: str) -> None:
        file_content_to_update = {self.CLIENT_ID_FIELD_NAME: client_id, self.ID_TOKEN_FIELD_NAME: id_token}
        self.write_content_to_file(file_content_to_update)

    def update_credentials(self, client_id: str, client_secret: str) -> None:
        file_content_to_update = {self.CLIENT_ID_FIELD_NAME: client_id, self.CLIENT_SECRET_FIELD_NAME: client_secret}
        self.write_content_to_file(file_content_to_update)

    def get_access_token(self) -> tuple[Optional[str], Optional[float], Optional[JwtCreator]]:
        file_content = self.read_file()

        access_token = file_content.get(self.ACCESS_TOKEN_FIELD_NAME)
        expires_in = file_content.get(self.ACCESS_TOKEN_EXPIRES_IN_FIELD_NAME)

        creator = None
        hashed_creator = file_content.get(self.ACCESS_TOKEN_CREATOR_FIELD_NAME)
        if hashed_creator:
            creator = JwtCreator(hashed_creator)

        setup_scope_from_access_token(access_token)

        return access_token, expires_in, creator

    def update_access_token(
        self, access_token: Optional[str], expires_in: Optional[float], creator: Optional[JwtCreator]
    ) -> None:
        file_content_to_update = {
            self.ACCESS_TOKEN_FIELD_NAME: access_token,
            self.ACCESS_TOKEN_EXPIRES_IN_FIELD_NAME: expires_in,
            self.ACCESS_TOKEN_CREATOR_FIELD_NAME: str(creator) if creator else None,
        }
        self.write_content_to_file(file_content_to_update)

        setup_scope_from_access_token(access_token)

    def get_filename(self) -> str:
        return os.path.join(self.HOME_PATH, self.CYCODE_HIDDEN_DIRECTORY, self.FILE_NAME)
