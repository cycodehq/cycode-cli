from typing import List, Dict
from marshmallow import Schema, fields, EXCLUDE, post_load


class Detection(Schema):
    def __init__(self, type: str, message: str, detection_details: dict, detection_rule_id: str):
        super().__init__()
        self.message = message
        self.type = type
        self.detection_details = detection_details
        self.detection_rule_id = detection_rule_id

    def __repr__(self) -> str:
        return (
            "type:{0}, "
            "message:{1}, "
            "detection_details: {2}"
            "detection_rule_id:{3}".format(self.type, self.message, repr(self.detection_details), self.detection_rule_id)
        )


class DetectionSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    message = fields.String()
    type = fields.String()
    detection_details = fields.Dict()
    detection_rule_id = fields.String()

    @post_load
    def build_dto(self, data, **kwargs):
        return Detection(**data)


class DetectionsPerFile(Schema):
    def __init__(self, file_name: str, detections: List[Detection]):
        super().__init__()
        self.file_name = file_name
        self.detections = detections


class DetectionsPerFileSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    file_name = fields.String()
    detections = fields.List(fields.Nested(DetectionSchema))

    @post_load
    def build_dto(self, data, **kwargs):
        return DetectionsPerFile(**data)


class ZippedFileScanResult(Schema):
    def __init__(self, did_detect: bool, detections_per_file: List[DetectionsPerFile], scan_id: str = None, err: str = None):
        super().__init__()
        self.did_detect = did_detect
        self.detections_per_file = detections_per_file
        self.scan_id = scan_id
        self.err = err


class ZippedFileScanResultSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    did_detect = fields.Boolean()
    scan_id = fields.String()
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
