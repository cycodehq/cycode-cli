import os
from pathlib import Path
from typing import Optional, Dict
from cli.user_settings.config_file_manager import ConfigFileManager
from cli.consts import DEFAULT_CYCODE_API_URL, CYCODE_API_URL_VAR_NAME, VERBOSE_ENV_VAR_NAME


class ConfigurationManager:
    global_config_file_manager: ConfigFileManager
    local_config_file_manager: ConfigFileManager

    def __init__(self):
        self.global_config_file_manager = ConfigFileManager(Path.home())
        self.local_config_file_manager = ConfigFileManager(os.getcwd())

    def get_base_url(self) -> str:
        base_url = self.get_base_url_from_environment_variables()
        if base_url is not None:
            return base_url

        base_url = self.local_config_file_manager.get_base_url()
        if base_url is not None:
            return base_url

        base_url = self.global_config_file_manager.get_base_url()
        if base_url is not None:
            return base_url

        return DEFAULT_CYCODE_API_URL

    def get_verbose_flag(self) -> bool:
        verbose_flag_env_var = self.get_verbose_flag_from_environment_variables()
        verbose_flag_local_config = self.local_config_file_manager.get_verbose_flag()
        verbose_flag_global_config = self.global_config_file_manager.get_verbose_flag()
        return verbose_flag_env_var or verbose_flag_local_config or verbose_flag_global_config

    def get_base_url_from_environment_variables(self) -> Optional[str]:
        return self._get_value_from_environment_variables(CYCODE_API_URL_VAR_NAME)


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

    def _get_value_from_environment_variables(self, env_var_name, default=None):
        return os.getenv(env_var_name, default)
