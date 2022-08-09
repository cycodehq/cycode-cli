import os
from typing import Optional, List, Dict
from cli.user_settings.base_file_manager import BaseFileManager
from cli.consts import CYCODE_CONFIGURATION_DIRECTORY


class ConfigFileManager(BaseFileManager):
    CYCODE_HIDDEN_DIRECTORY: str = CYCODE_CONFIGURATION_DIRECTORY
    FILE_NAME: str = 'config.yaml'

    ENVIRONMENT_SECTION_NAME: str = 'environment'
    EXCLUSIONS_SECTION_NAME: str = 'exclusions'

    API_URL_FIELD_NAME: str = 'cycode_api_url'
    APP_URL_FIELD_NAME: str = 'cycode_app_url'
    VERBOSE_FIELD_NAME: str = 'verbose'

    def __init__(self, path):
        self.path = path

    def get_api_url(self) -> Optional[str]:
        return self._get_value_from_environment_section(self.API_URL_FIELD_NAME)

    def get_app_url(self) -> Optional[str]:
        return self._get_value_from_environment_section(self.APP_URL_FIELD_NAME)

    def get_verbose_flag(self) -> Optional[bool]:
        return self._get_value_from_environment_section(self.VERBOSE_FIELD_NAME)

    def get_exclusions_by_scan_type(self, scan_type) -> Dict:
        file_content = self.read_file()
        exclusions_section = file_content.get(self.EXCLUSIONS_SECTION_NAME, {})
        scan_type_exclusions = exclusions_section.get(scan_type, {})
        return scan_type_exclusions

    def update_base_url(self, base_url: str):
        update_data = {
            self.ENVIRONMENT_SECTION_NAME: {
                self.API_URL_FIELD_NAME: base_url
            }
        }
        self.write_content_to_file(update_data)

    def add_exclusion(self, scan_type, exclusion_type, new_exclusion):
        exclusions = self._get_exclusions_by_exclusion_type(scan_type, exclusion_type)
        if new_exclusion in exclusions:
            return

        exclusions.append(new_exclusion)

        update_data = {
            self.EXCLUSIONS_SECTION_NAME: {
                scan_type: {
                    exclusion_type: exclusions
                }
            }
        }
        self.write_content_to_file(update_data)

    def get_config_directory_path(self) -> str:
        return os.path.join(self.path, self.CYCODE_HIDDEN_DIRECTORY)

    def get_filename(self) -> str:
        return os.path.join(self.get_config_directory_path(), self.FILE_NAME)

    @staticmethod
    def get_config_file_route() -> str:
        return os.path.join(ConfigFileManager.CYCODE_HIDDEN_DIRECTORY, ConfigFileManager.FILE_NAME)

    def _get_exclusions_by_exclusion_type(self, scan_type, exclusion_type) -> List:
        scan_type_exclusions = self.get_exclusions_by_scan_type(scan_type)
        return scan_type_exclusions.get(exclusion_type, [])

    def _get_value_from_environment_section(self, field_name: str):
        file_content = self.read_file()
        environment_section = file_content.get(self.ENVIRONMENT_SECTION_NAME, {})
        value = environment_section.get(field_name)
        return value
