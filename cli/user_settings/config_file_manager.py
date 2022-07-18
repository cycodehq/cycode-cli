import os
from typing import Optional, List, Dict
from cli.user_settings.base_file_manager import BaseFileManager
from cli.consts import CYCODE_CONFIGURATION_DIRECTORY


class ConfigFileManager(BaseFileManager):
    CYCODE_HIDDEN_DIRECTORY: str = CYCODE_CONFIGURATION_DIRECTORY
    FILE_NAME: str = 'config.yaml'

    ENVIRONMENT_SECTION_NAME: str = 'environment'
    EXCLUSIONS_SECTION_NAME: str = 'exclusions'

    BASE_URL_FIELD_NAME: str = 'cycode_base_url'
    VERBOSE_FIELD_NAME: str = 'verbose'

    def __init__(self, path):
        self.path = path

    def get_base_url(self) -> Optional[str]:
        file_content = self.read_file()

        environment_section = file_content.get(self.ENVIRONMENT_SECTION_NAME, {})
        base_url = environment_section.get(self.BASE_URL_FIELD_NAME)
        return base_url

    def get_verbose_flag(self) -> Optional[bool]:
        file_content = self.read_file()

        environment_section = file_content.get(self.ENVIRONMENT_SECTION_NAME, {})
        verbose_flag = environment_section.get(self.VERBOSE_FIELD_NAME)
        return verbose_flag

    def get_exclusions_by_scan_type(self, scan_type) -> Dict:
        file_content = self.read_file()
        exclusions_section = file_content.get(self.EXCLUSIONS_SECTION_NAME, {})
        scan_type_exclusions = exclusions_section.get(scan_type, {})
        return scan_type_exclusions

    def update_base_url(self, base_url: str):
        update_data = {
            self.ENVIRONMENT_SECTION_NAME: {
                self.BASE_URL_FIELD_NAME: base_url
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

    def _get_exclusions_by_exclusion_type(self, scan_type, exclusion_type) -> List:
        scan_type_exclusions = self.get_exclusions_by_scan_type(scan_type)
        return scan_type_exclusions.get(exclusion_type, [])
