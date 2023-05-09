import os
from pathlib import Path
from typing import Optional, Dict

from cycode.cli.user_settings.config_file_manager import ConfigFileManager
from cycode.cli.consts import *


class ConfigurationManager:
    global_config_file_manager: ConfigFileManager
    local_config_file_manager: ConfigFileManager

    def __init__(self):
        self.global_config_file_manager = ConfigFileManager(Path.home())
        self.local_config_file_manager = ConfigFileManager(os.getcwd())

    def get_cycode_api_url(self) -> str:
        api_url = self.get_api_url_from_environment_variables()
        if api_url is not None:
            return api_url

        api_url = self.local_config_file_manager.get_api_url()
        if api_url is not None:
            return api_url

        api_url = self.global_config_file_manager.get_api_url()
        if api_url is not None:
            return api_url

        return DEFAULT_CYCODE_API_URL

    def get_cycode_app_url(self) -> str:
        app_url = self.get_app_url_from_environment_variables()
        if app_url is not None:
            return app_url

        app_url = self.local_config_file_manager.get_app_url()
        if app_url is not None:
            return app_url

        app_url = self.global_config_file_manager.get_app_url()
        if app_url is not None:
            return app_url

        return DEFAULT_CYCODE_APP_URL

    def get_verbose_flag(self) -> bool:
        verbose_flag_env_var = self.get_verbose_flag_from_environment_variables()
        verbose_flag_local_config = self.local_config_file_manager.get_verbose_flag()
        verbose_flag_global_config = self.global_config_file_manager.get_verbose_flag()
        return verbose_flag_env_var or verbose_flag_local_config or verbose_flag_global_config

    def get_api_url_from_environment_variables(self) -> Optional[str]:
        return self._get_value_from_environment_variables(CYCODE_API_URL_ENV_VAR_NAME)

    def get_app_url_from_environment_variables(self) -> Optional[str]:
        return self._get_value_from_environment_variables(CYCODE_APP_URL_ENV_VAR_NAME)

    def get_verbose_flag_from_environment_variables(self) -> bool:
        value = self._get_value_from_environment_variables(VERBOSE_ENV_VAR_NAME, '')
        return value.lower() in ('true', '1')

    def get_exclusions_by_scan_type(self, scan_type) -> Dict:
        local_exclusions = self.local_config_file_manager.get_exclusions_by_scan_type(scan_type)
        global_exclusions = self.global_config_file_manager.get_exclusions_by_scan_type(scan_type)
        return self._merge_exclusions(local_exclusions, global_exclusions)

    def add_exclusion(self, scope: str, scan_type: str, exclusion_type: str, value: str):
        config_file_manager = self.get_config_file_manager(scope)
        config_file_manager.add_exclusion(scan_type, exclusion_type, value)

    def _merge_exclusions(self, local_exclusions: Dict, global_exclusions: Dict) -> Dict:
        keys = set(list(local_exclusions.keys()) + list(global_exclusions.keys()))
        return {key: local_exclusions.get(key, []) + global_exclusions.get(key, []) for key in keys}

    def update_base_url(self, base_url: str, scope: str = 'local'):
        config_file_manager = self.get_config_file_manager(scope)
        config_file_manager.update_base_url(base_url)

    def get_config_file_manager(self, scope):
        return self.local_config_file_manager if scope == 'local' else self.global_config_file_manager

    def get_scan_polling_timeout_in_seconds(self) -> int:
        return int(self._get_value_from_environment_variables(SCAN_POLLING_TIMEOUT_IN_SECONDS_ENV_VAR_NAME,
                                                              DEFAULT_SCAN_POLLING_TIMEOUT_IN_SECONDS))

    def get_sca_pre_commit_timeout_in_seconds(self) -> int:
        return int(self._get_value_from_environment_variables(SCA_PRE_COMMIT_TIMEOUT_IN_SECONDS_ENV_VAR_NAME,
                                                              DEFAULT_SCA_PRE_COMMIT_TIMEOUT_IN_SECONDS))

    def get_pre_receive_max_commits_to_scan_count(self, command_scan_type: str) -> int:
        max_commits = self._get_value_from_environment_variables(PRE_RECEIVE_MAX_COMMITS_TO_SCAN_COUNT_ENV_VAR_NAME)
        if max_commits is not None:
            return int(max_commits)

        max_commits = self.local_config_file_manager.get_max_commits(command_scan_type)
        if max_commits is not None:
            return max_commits

        max_commits = self.global_config_file_manager.get_max_commits(command_scan_type)
        if max_commits is not None:
            return max_commits

        return DEFAULT_PRE_RECEIVE_MAX_COMMITS_TO_SCAN_COUNT

    def get_pre_receive_command_timeout(self, command_scan_type: str) -> int:
        command_timeout = self._get_value_from_environment_variables(PRE_RECEIVE_COMMAND_TIMEOUT_ENV_VAR_NAME)
        if command_timeout is not None:
            return int(command_timeout)

        command_timeout = self.local_config_file_manager.get_command_timeout(command_scan_type)
        if command_timeout is not None:
            return command_timeout

        command_timeout = self.global_config_file_manager.get_command_timeout(command_scan_type)
        if command_timeout is not None:
            return command_timeout

        return DEFAULT_PRE_RECEIVE_COMMAND_TIMEOUT_IN_SECONDS

    def get_should_exclude_detections_in_deleted_lines(self, command_scan_type: str) -> bool:
        exclude_detections_in_deleted_lines = self._get_value_from_environment_variables(
            EXCLUDE_DETECTIONS_IN_DELETED_LINES_ENV_VAR_NAME)
        if exclude_detections_in_deleted_lines is not None:
            return exclude_detections_in_deleted_lines.lower() in ('true', '1')

        exclude_detections_in_deleted_lines = self.local_config_file_manager \
            .get_exclude_detections_in_deleted_lines(command_scan_type)
        if exclude_detections_in_deleted_lines is not None:
            return exclude_detections_in_deleted_lines

        exclude_detections_in_deleted_lines = self.global_config_file_manager\
            .get_exclude_detections_in_deleted_lines(command_scan_type)
        if exclude_detections_in_deleted_lines is not None:
            return exclude_detections_in_deleted_lines

        return DEFAULT_EXCLUDE_DETECTIONS_IN_DELETED_LINES

    @staticmethod
    def _get_value_from_environment_variables(env_var_name, default=None):
        return os.getenv(env_var_name, default)
