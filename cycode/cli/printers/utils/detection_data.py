from pathlib import Path
from typing import TYPE_CHECKING, Optional

from cycode.cli import consts

if TYPE_CHECKING:
    from cycode.cyclient.models import Detection


def get_cwe_cve_link(cwe_cve: Optional[str]) -> Optional[str]:
    if not cwe_cve:
        return None

    if cwe_cve.startswith('GHSA'):
        return f'https://github.com/advisories/{cwe_cve}'

    if cwe_cve.startswith('CWE'):
        # string example: 'CWE-532: Insertion of Sensitive Information into Log File'
        parts = cwe_cve.split('-')
        if len(parts) < 1:
            return None

        number = ''
        for char in parts[1]:
            if char.isdigit():
                number += char
            else:
                break

        return f'https://cwe.mitre.org/data/definitions/{number}'

    if cwe_cve.startswith('CVE'):
        return f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cwe_cve}'

    return None


def clear_cwe_name(cwe: str) -> str:
    """Clear CWE.

    Intput: CWE-532: Insertion of Sensitive Information into Log File
    Output: CWE-532
    """
    if cwe.startswith('CWE'):
        return cwe.split(':')[0]

    return cwe


def get_detection_clickable_cwe_cve(scan_type: str, detection: 'Detection') -> str:
    def link(url: str, name: str) -> str:
        return f'[link={url}]{clear_cwe_name(name)}[/]'

    if scan_type == consts.SCA_SCAN_TYPE:
        cve = detection.detection_details.get('vulnerability_id')
        return link(get_cwe_cve_link(cve), cve) if cve else ''
    if scan_type == consts.SAST_SCAN_TYPE:
        renderables = []
        for cwe in detection.detection_details.get('cwe', []):
            cwe and renderables.append(link(get_cwe_cve_link(cwe), cwe))
        return ', '.join(renderables)

    return ''


def get_detection_cwe_cve(scan_type: str, detection: 'Detection') -> Optional[str]:
    if scan_type == consts.SCA_SCAN_TYPE:
        return detection.detection_details.get('vulnerability_id')
    if scan_type == consts.SAST_SCAN_TYPE:
        cwes = detection.detection_details.get('cwe')  # actually it is List[str]
        if not cwes:
            return None

        return ' | '.join(cwes)

    return None


def get_detection_title(scan_type: str, detection: 'Detection') -> str:
    title = detection.message
    if scan_type == consts.SAST_SCAN_TYPE:
        title = detection.detection_details['policy_display_name']
    elif scan_type == consts.SECRET_SCAN_TYPE:
        title = f'Hardcoded {detection.type} is used'

    is_sca_package_vulnerability = scan_type == consts.SCA_SCAN_TYPE and detection.has_alert
    if is_sca_package_vulnerability:
        title = detection.detection_details['alert'].get('summary', 'N/A')

    cwe_cve = get_detection_cwe_cve(scan_type, detection)
    return f'[{cwe_cve}] {title}' if cwe_cve else title


def get_detection_file_path(scan_type: str, detection: 'Detection') -> Path:
    if scan_type == consts.SECRET_SCAN_TYPE:
        folder_path = detection.detection_details.get('file_path', '')
        file_name = detection.detection_details.get('file_name', '')
        return Path.joinpath(Path(folder_path), Path(file_name))
    if scan_type == consts.SAST_SCAN_TYPE:
        file_path = detection.detection_details.get('file_path', '')

        # fix the absolute path...BE returns string which does not start with /
        if not file_path.startswith('/'):
            file_path = f'/{file_path}'

        return Path(file_path)

    return Path(detection.detection_details.get('file_name', ''))
