from typing import TYPE_CHECKING

from cycode.cli import consts

if TYPE_CHECKING:
    from cycode.cyclient.models import Detection


def get_detection_title(scan_type: str, detection: 'Detection') -> str:
    title = detection.message
    if scan_type == consts.SAST_SCAN_TYPE:
        title = detection.detection_details['policy_display_name']
    elif scan_type == consts.SECRET_SCAN_TYPE:
        title = f'Hardcoded {detection.type} is used'

    return title
