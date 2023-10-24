from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from marshmallow import EXCLUDE, Schema, fields, post_load


class Detection(Schema):
    def __init__(
        self,
        detection_type_id: str,
        type: str,
        message: str,
        detection_details: dict,
        detection_rule_id: str,
        severity: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.message = message
        self.type = type
        self.severity = severity
        self.detection_type_id = detection_type_id
        self.detection_details = detection_details
        self.detection_rule_id = detection_rule_id

    def __repr__(self) -> str:
        return (
            f'type:{self.type}, '
            f'severity:{self.severity}, '
            f'message:{self.message}, '
            f'detection_details:{self.detection_details!r}, '
            f'detection_rule_id:{self.detection_rule_id}'
        )


class DetectionSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    message = fields.String()
    type = fields.String()
    severity = fields.String(missing='High')
    # TODO(MarshalX): Remove "missing" arg when IaC and Secrets scans will have classifications
    detection_type_id = fields.String()
    detection_details = fields.Dict()
    detection_rule_id = fields.String()

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> Detection:
        return Detection(**data)


class DetectionsPerFile(Schema):
    def __init__(self, file_name: str, detections: List[Detection], commit_id: Optional[str] = None) -> None:
        super().__init__()
        self.file_name = file_name
        self.detections = detections
        self.commit_id = commit_id


class DetectionsPerFileSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    file_name = fields.String()
    detections = fields.List(fields.Nested(DetectionSchema))
    commit_id = fields.String(allow_none=True)

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'DetectionsPerFile':
        return DetectionsPerFile(**data)


class ZippedFileScanResult(Schema):
    def __init__(
        self,
        did_detect: bool,
        detections_per_file: List[DetectionsPerFile],
        report_url: Optional[str] = None,
        scan_id: Optional[str] = None,
        err: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.did_detect = did_detect
        self.detections_per_file = detections_per_file
        self.scan_id = scan_id
        self.report_url = report_url
        self.err = err


class ZippedFileScanResultSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    did_detect = fields.Boolean()
    scan_id = fields.String()
    report_url = fields.String(allow_none=True)
    detections_per_file = fields.List(fields.Nested(DetectionsPerFileSchema))
    err = fields.String()

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'ZippedFileScanResult':
        return ZippedFileScanResult(**data)


class ScanResult(Schema):
    def __init__(
        self,
        did_detect: bool,
        scan_id: Optional[str] = None,
        detections: Optional[List[Detection]] = None,
        err: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.did_detect = did_detect
        self.scan_id = scan_id
        self.detections = detections
        self.err = err


class ScanResultSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    did_detect = fields.Boolean()
    scan_id = fields.String()
    detections = fields.List(fields.Nested(DetectionSchema), required=False, allow_none=True)
    err = fields.String()

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'ScanResult':
        return ScanResult(**data)


class ScanInitializationResponse(Schema):
    def __init__(self, scan_id: Optional[str] = None, err: Optional[str] = None) -> None:
        super().__init__()
        self.scan_id = scan_id
        self.err = err


class ScanInitializationResponseSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    scan_id = fields.String()
    err = fields.String()

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'ScanInitializationResponse':
        return ScanInitializationResponse(**data)


class ScanDetailsResponse(Schema):
    def __init__(
        self,
        id: Optional[str] = None,
        scan_status: Optional[str] = None,
        results_count: Optional[int] = None,
        metadata: Optional[str] = None,
        message: Optional[str] = None,
        scan_update_at: Optional[str] = None,
        err: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.id = id
        self.scan_status = scan_status
        self.detections_count = results_count
        self.metadata = metadata
        self.message = message
        self.scan_update_at = scan_update_at
        self.err = err


class ScanDetailsResponseSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    id = fields.String()
    scan_status = fields.String()
    results_count = fields.Integer(allow_none=True)
    metadata = fields.String(allow_none=True)
    message = fields.String(allow_none=True)
    scan_update_at = fields.String(allow_none=True)
    err = fields.String()

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'ScanDetailsResponse':
        return ScanDetailsResponse(**data)


class K8SResource:
    def __init__(self, name: str, resource_type: str, namespace: str, content: Dict) -> None:
        super().__init__()
        self.name = name
        self.type = resource_type
        self.namespace = namespace
        self.content = content
        self.internal_metadata = None
        self.schema = K8SResourceSchema()

    def to_json(self) -> dict:  # FIXME(MarshalX): rename to to_dict?
        return self.schema.dump(self)


class InternalMetadata:
    def __init__(self, root_entity_name: str, root_entity_type: str) -> None:
        super().__init__()
        self.root_entity_name = root_entity_name
        self.root_entity_type = root_entity_type
        self.schema = InternalMetadataSchema()

    def to_json(self) -> dict:  # FIXME(MarshalX): rename to to_dict?
        return self.schema.dump(self)


class ResourcesCollection:
    def __init__(self, resource_type: str, namespace: str, resources: List[K8SResource], total_count: int) -> None:
        super().__init__()
        self.type = resource_type
        self.namespace = namespace
        self.resources = resources
        self.total_count = total_count
        self.schema = ResourcesCollectionSchema()

    def to_json(self) -> dict:  # FIXME(MarshalX): rename to to_dict?
        return self.schema.dump(self)


class InternalMetadataSchema(Schema):
    root_entity_name = fields.String()
    root_entity_type = fields.String()


class K8SResourceSchema(Schema):
    name = fields.String()
    type = fields.String()
    namespace = fields.String()
    content = fields.Dict()
    internal_metadata = fields.Nested(InternalMetadataSchema)


class ResourcesCollectionSchema(Schema):
    type = fields.String()
    namespace = fields.String()
    resources = fields.List(fields.Nested(K8SResourceSchema))
    total_count = fields.Integer()


class OwnerReference:
    def __init__(self, name: str, kind: str) -> None:
        super().__init__()
        self.name = name
        self.kind = kind

    def __str__(self) -> str:
        return 'Name: {0}, Kind: {1}'.format(self.name, self.kind)


class AuthenticationSession(Schema):
    def __init__(self, session_id: str) -> None:
        super().__init__()
        self.session_id = session_id


class AuthenticationSessionSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    session_id = fields.String()

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'AuthenticationSession':
        return AuthenticationSession(**data)


class ApiToken(Schema):
    def __init__(self, client_id: str, secret: str, description: str) -> None:
        super().__init__()
        self.client_id = client_id
        self.secret = secret
        self.description = description


class ApiTokenSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    client_id = fields.String(data_key='clientId')
    secret = fields.String()
    description = fields.String()

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'ApiToken':
        return ApiToken(**data)


class ApiTokenGenerationPollingResponse(Schema):
    def __init__(self, status: str, api_token: 'ApiToken') -> None:
        super().__init__()
        self.status = status
        self.api_token = api_token


class ApiTokenGenerationPollingResponseSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    status = fields.String()
    api_token = fields.Nested(ApiTokenSchema, allow_none=True)

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'ApiTokenGenerationPollingResponse':
        return ApiTokenGenerationPollingResponse(**data)


class UserAgentOptionScheme(Schema):
    app_name = fields.String(required=True)  # ex. vscode_extension
    app_version = fields.String(required=True)  # ex. 0.2.3
    env_name = fields.String(required=True)  # ex.: Visual Studio Code
    env_version = fields.String(required=True)  # ex. 1.78.2

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> 'UserAgentOption':
        return UserAgentOption(**data)


@dataclass
class UserAgentOption:
    app_name: str
    app_version: str
    env_name: str
    env_version: str

    @property
    def user_agent_suffix(self) -> str:
        """Returns suffix of User-Agent.

        Example: vscode_extension (AppVersion: 0.1.2; EnvName: vscode; EnvVersion: 1.78.2)
        """
        return (
            f'{self.app_name} '
            f'('
            f'AppVersion: {self.app_version}; '
            f'EnvName: {self.env_name}; EnvVersion: {self.env_version}'
            f')'
        )


@dataclass
class SbomReportStorageDetails:
    path: str
    folder: str
    size: int


class SbomReportStorageDetailsSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    path = fields.String()
    folder = fields.String()
    size = fields.Integer()

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> SbomReportStorageDetails:
        return SbomReportStorageDetails(**data)


@dataclass
class ReportExecution:
    id: int
    status: str
    error_message: Optional[str] = None
    status_message: Optional[str] = None
    storage_details: Optional[SbomReportStorageDetails] = None


class ReportExecutionSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    id = fields.Integer()
    status = fields.String()
    error_message = fields.String(allow_none=True)
    status_message = fields.String(allow_none=True)
    storage_details = fields.Nested(SbomReportStorageDetailsSchema, allow_none=True)

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> ReportExecution:
        return ReportExecution(**data)


@dataclass
class SbomReport:
    report_executions: List[ReportExecution]


class RequestedSbomReportResultSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    report_executions = fields.List(fields.Nested(ReportExecutionSchema))

    @post_load
    def build_dto(self, data: Dict[str, Any], **_) -> SbomReport:
        return SbomReport(**data)
