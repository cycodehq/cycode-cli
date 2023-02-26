class ScanConfigBase:
    def __init__(self):
        self.SCAN_CONTROLLER_PATH = 'api/v1/scan'
        self.DETECTIONS_SERVICE_CONTROLLER_PATH = 'api/v1/detections'

    def get_service_name(self, scan_type):
        pass

    def get_scans_prefix(self):
        pass

    def get_detections_prefix(self):
        pass

    def get_content_scan_controller_path(self, scan_type):
        return f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/content"

    def get_scan_controller_path(self, scan_type):
        return f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}"

    def get_zipped_file_scan_controller_path(self, scan_type):
        return f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/zipped-file"

    def get_zipped_file_scan_async_controller_path(self, scan_type):
        return f"{self.get_scans_prefix()}/{self.SCAN_CONTROLLER_PATH}/{scan_type}/repository"

    def get_repository_commit_range_scan_async_controller_path(self, scan_type):
        return f"{self.get_scans_prefix()}/{self.SCAN_CONTROLLER_PATH}/{scan_type}/repository/commit-range"

    def get_scan_details_controller_path(self, scan_id):
        return f"{self.get_scans_prefix()}/{self.SCAN_CONTROLLER_PATH}/{scan_id}"

    def get_scan_detections_controller_path(self, scan_id, page_size, page_number):
        return f"{self.get_detections_prefix()}/{self.DETECTIONS_SERVICE_CONTROLLER_PATH}?scan_id={scan_id}&page_size={page_size}&page_number={page_number}"

    def get_scan_detections_count_controller_path(self, scan_id):
        return f"{self.get_detections_prefix()}/{self.DETECTIONS_SERVICE_CONTROLLER_PATH}?scan_id={scan_id}"

    def get_commit_range_zipped_file_scan_controller_path(self, scan_type):
        return f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/commit-range-zipped-file"

    def get_report_scan_status_controller_path(self, scan_type, scan_id):
        return f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/{scan_id}/status"


class DevScanConfig(ScanConfigBase):
    def __init__(self):
        super().__init__()

    def get_service_name(self, scan_type):
        if scan_type == 'secret':
            return '5025'
        elif scan_type == 'iac':
            return '5026'
        elif scan_type == 'sca' or scan_type == 'sast':
            return '5004'

    def get_scans_prefix(self):
        return '5004'

    def get_detections_prefix(self):
        return '5016'


class DefaultScanConfig(ScanConfigBase):
    def __init__(self):
        super().__init__()

    def get_service_name(self, scan_type):
        if scan_type == 'secret':
            return 'secret'
        elif scan_type == 'iac':
            return 'iac'
        elif scan_type == 'sca' or scan_type == 'sast':
            return 'scans'

    def get_scans_prefix(self):
        return 'scans'

    def get_detections_prefix(self):
        return 'detections'