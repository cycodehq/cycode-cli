from typing import List, Dict, Optional
from marshmallow import Schema, fields, EXCLUDE, post_load


class Detection(Schema):
    def __init__(self, detection_type_id: str, type: str, message: str, detection_details: dict,
                 detection_rule_id: str, severity: Optional[str] = None):
        super().__init__()
        self.message = message
        self.type = type
        self.severity = severity
        self.detection_type_id = detection_type_id
        self.detection_details = detection_details
        self.detection_rule_id = detection_rule_id

    def __repr__(self) -> str:
        return f'type:{self.type}, ' \
               f'severity:{self.severity}, ' \
               f'message:{self.message}, ' \
               f'detection_details:{repr(self.detection_details)}, ' \
               f'detection_rule_id:{self.detection_rule_id}'


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
    def build_dto(self, data, **kwargs):
        return Detection(**data)


class DetectionsPerFile(Schema):
    def __init__(self, file_name: str, detections: List[Detection], commit_id: Optional[str] = None):
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
    def build_dto(self, data, **kwargs):
        return DetectionsPerFile(**data)


class ZippedFileScanResult(Schema):
    def __init__(self, did_detect: bool, detections_per_file: List[DetectionsPerFile], report_url: Optional[str] = None,
                 scan_id: str = None, err: str = None):
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
    detections_per_file = fields.List(
        fields.Nested(DetectionsPerFileSchema))
    err = fields.String()

    @post_load
    def build_dto(self, data, **kwargs):
        return ZippedFileScanResult(**data)


class ScanResult(Schema):
    def __init__(self, did_detect: bool, scan_id: str = None, detections: List[Detection] = None, err: str = None):
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
    detections = fields.List(
        fields.Nested(DetectionSchema), required=False, allow_none=True)
    err = fields.String()

    @post_load
    def build_dto(self, data, **kwargs):
        return ScanResult(**data)


class ScanInitializationResponse(Schema):
    def __init__(self, scan_id: str = None, err: str = None):
        super().__init__()
        self.scan_id = scan_id
        self.err = err


class ScanInitializationResponseSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    scan_id = fields.String()
    err = fields.String()

    @post_load
    def build_dto(self, data, **kwargs):
        return ScanInitializationResponse(**data)


class ScanDetailsResponse(Schema):
    def __init__(self, id: str = None, scan_status: str = None, results_count: int = None, metadata: str = None, message: str = None,
                 scan_update_at: str = None, err: str = None):
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
    def build_dto(self, data, **kwargs):
        return ScanDetailsResponse(**data)


class K8SResource:
    def __init__(self, name: str, resource_type: str, namespace: str, content: Dict):
        super().__init__()
        self.name = name
        self.type = resource_type
        self.namespace = namespace
        self.content = content
        self.internal_metadata = None
        self.schema = K8SResourceSchema()

    def to_json(self):
        return self.schema.dump(self)


class InternalMetadata:
    def __init__(self, root_entity_name: str, root_entity_type: str):
        super().__init__()
        self.root_entity_name = root_entity_name
        self.root_entity_type = root_entity_type
        self.schema = InternalMetadataSchema()

    def to_json(self):
        return self.schema.dump(self)


class ResourcesCollection:
    def __init__(self, resource_type: str, namespace: str, resources: List[K8SResource], total_count: int):
        super().__init__()
        self.type = resource_type
        self.namespace = namespace
        self.resources = resources
        self.total_count = total_count
        self.schema = ResourcesCollectionSchema()

    def to_json(self):
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
    def __init__(self, name: str, kind: str):
        super().__init__()
        self.name = name
        self.kind = kind

    def __str__(self):
        return "Name: {0}, Kind: {1}".format(self.name, self.kind)


class AuthenticationSession(Schema):
    def __init__(self, session_id: str):
        super().__init__()
        self.session_id = session_id


class AuthenticationSessionSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    session_id = fields.String()

    @post_load
    def build_dto(self, data, **kwargs):
        return AuthenticationSession(**data)


class ApiToken(Schema):
    def __init__(self, client_id: str, secret: str, description: str):
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
    def build_dto(self, data, **kwargs):
        return ApiToken(**data)


class ApiTokenGenerationPollingResponse(Schema):
    def __init__(self, status: str, api_token):
        super().__init__()
        self.status = status
        self.api_token = api_token


class ApiTokenGenerationPollingResponseSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    status = fields.String()
    api_token = fields.Nested(ApiTokenSchema, allow_none=True)

    @post_load
    def build_dto(self, data, **kwargs):
        return ApiTokenGenerationPollingResponse(**data)
