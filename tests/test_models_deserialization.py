from cycode.cyclient.models import (
    ApiToken,
    ApiTokenGenerationPollingResponse,
    ApiTokenGenerationPollingResponseSchema,
    ApiTokenSchema,
    AuthenticationSession,
    AuthenticationSessionSchema,
    ClassificationData,
    ClassificationDataSchema,
    Detection,
    DetectionRule,
    DetectionRuleSchema,
    DetectionSchema,
    Member,
    MemberDetails,
    MemberSchema,
    ReportExecution,
    ReportExecutionSchema,
    RequestedMemberDetailsResultSchema,
    RequestedSbomReportResultSchema,
    SbomReport,
    SbomReportStorageDetails,
    SbomReportStorageDetailsSchema,
    ScanConfiguration,
    ScanConfigurationSchema,
    ScanInitializationResponse,
    ScanInitializationResponseSchema,
    ScanResult,
    ScanResultSchema,
    ScanResultsSyncFlow,
    ScanResultsSyncFlowSchema,
    SupportedModulesPreferences,
    SupportedModulesPreferencesSchema,
    UserAgentOption,
    UserAgentOptionScheme,
)

# --- DetectionSchema ---


def test_detection_schema_load() -> None:
    raw = {
        'id': 'det-123',
        'message': 'API key exposed',
        'type': 'secret',
        'severity': 'critical',
        'detection_type_id': 'secret-1',
        'detection_details': {'alert': True, 'value': 'sk_live_xxx'},
        'detection_rule_id': 'rule-456',
    }
    result = DetectionSchema().load(raw)
    assert isinstance(result, Detection)
    assert result.id == 'det-123'
    assert result.message == 'API key exposed'
    assert result.type == 'secret'
    assert result.severity == 'critical'
    assert result.detection_type_id == 'secret-1'
    assert result.detection_details == {'alert': True, 'value': 'sk_live_xxx'}
    assert result.detection_rule_id == 'rule-456'


def test_detection_schema_load_defaults() -> None:
    raw = {
        'message': 'Vulnerability found',
        'type': 'sca',
        'detection_type_id': 'vuln-1',
        'detection_details': {},
        'detection_rule_id': 'rule-789',
    }
    result = DetectionSchema().load(raw)
    assert result.id is None
    assert result.severity is None


def test_detection_schema_excludes_unknown_fields() -> None:
    raw = {
        'message': 'Test',
        'type': 'test',
        'detection_type_id': 'test-1',
        'detection_details': {},
        'detection_rule_id': 'test-rule',
        'unknown_field': 'should_be_ignored',
        'another_unknown': 123,
    }
    result = DetectionSchema().load(raw)
    assert isinstance(result, Detection)
    assert not hasattr(result, 'unknown_field')


def test_detection_has_alert_true() -> None:
    detection = Detection(
        detection_type_id='secret-1',
        type='secret',
        message='Key found',
        detection_details={'alert': {'severity': 'high'}},
        detection_rule_id='rule-1',
    )
    assert detection.has_alert is True


def test_detection_has_alert_false() -> None:
    detection = Detection(
        detection_type_id='license-1',
        type='sca',
        message='License issue',
        detection_details={'license': 'GPL'},
        detection_rule_id='rule-2',
    )
    assert detection.has_alert is False


def test_detection_repr() -> None:
    detection = Detection(
        detection_type_id='secret-1',
        type='secret',
        message='API key exposed',
        detection_details={'value': 'sk_live_xxx'},
        detection_rule_id='rule-1',
        severity='critical',
    )
    repr_str = repr(detection)
    assert 'secret' in repr_str
    assert 'critical' in repr_str
    assert 'API key exposed' in repr_str
    assert 'rule-1' in repr_str


# --- ScanResultSchema ---


def test_scan_result_schema_load_with_detections() -> None:
    raw = {
        'did_detect': True,
        'scan_id': 'scan-abc',
        'detections': [
            {
                'id': 'det-1',
                'message': 'Secret found',
                'type': 'secret',
                'detection_type_id': 'secret-1',
                'detection_details': {'alert': {}},
                'detection_rule_id': 'rule-1',
            }
        ],
        'err': '',
    }
    result = ScanResultSchema().load(raw)
    assert isinstance(result, ScanResult)
    assert result.did_detect is True
    assert result.scan_id == 'scan-abc'
    assert len(result.detections) == 1
    assert isinstance(result.detections[0], Detection)
    assert result.detections[0].id == 'det-1'


def test_scan_result_schema_load_no_detections() -> None:
    raw = {
        'did_detect': False,
        'scan_id': 'scan-def',
        'detections': None,
        'err': 'No files to scan',
    }
    result = ScanResultSchema().load(raw)
    assert result.did_detect is False
    assert result.detections is None
    assert result.err == 'No files to scan'


def test_scan_result_schema_excludes_unknown_fields() -> None:
    raw = {
        'did_detect': False,
        'scan_id': 'scan-1',
        'detections': None,
        'err': '',
        'extra_field': 'ignored',
    }
    result = ScanResultSchema().load(raw)
    assert isinstance(result, ScanResult)


# --- ScanInitializationResponseSchema ---


def test_scan_initialization_response_schema_load() -> None:
    raw = {'scan_id': 'scan-init-123', 'err': ''}
    result = ScanInitializationResponseSchema().load(raw)
    assert isinstance(result, ScanInitializationResponse)
    assert result.scan_id == 'scan-init-123'


# --- AuthenticationSessionSchema ---


def test_authentication_session_schema_load() -> None:
    raw = {'session_id': 'sess-123'}
    result = AuthenticationSessionSchema().load(raw)
    assert isinstance(result, AuthenticationSession)
    assert result.session_id == 'sess-123'


# --- ApiTokenSchema (tests data_key mapping) ---


def test_api_token_schema_load_data_key() -> None:
    raw = {
        'clientId': 'client-123',
        'secret': 'secret-456',
        'description': 'My API Token',
    }
    result = ApiTokenSchema().load(raw)
    assert isinstance(result, ApiToken)
    assert result.client_id == 'client-123'
    assert result.secret == 'secret-456'
    assert result.description == 'My API Token'


# --- ApiTokenGenerationPollingResponseSchema (nested) ---


def test_api_token_generation_polling_schema_load() -> None:
    raw = {
        'status': 'completed',
        'api_token': {
            'clientId': 'client-abc',
            'secret': 'secret-xyz',
            'description': 'Generated token',
        },
    }
    result = ApiTokenGenerationPollingResponseSchema().load(raw)
    assert isinstance(result, ApiTokenGenerationPollingResponse)
    assert result.status == 'completed'
    assert isinstance(result.api_token, ApiToken)
    assert result.api_token.client_id == 'client-abc'


def test_api_token_generation_polling_schema_load_null_token() -> None:
    raw = {
        'status': 'pending',
        'api_token': None,
    }
    result = ApiTokenGenerationPollingResponseSchema().load(raw)
    assert result.status == 'pending'
    assert result.api_token is None


# --- SbomReportStorageDetailsSchema / ReportExecutionSchema / RequestedSbomReportResultSchema ---


def test_sbom_report_storage_details_schema_load() -> None:
    raw = {'path': '/reports/sbom.json', 'folder': '/reports', 'size': 4096}
    result = SbomReportStorageDetailsSchema().load(raw)
    assert isinstance(result, SbomReportStorageDetails)
    assert result.path == '/reports/sbom.json'
    assert result.size == 4096


def test_report_execution_schema_load() -> None:
    raw = {
        'id': 1,
        'status': 'completed',
        'error_message': None,
        'status_message': 'Success',
        'storage_details': {'path': '/reports/sbom.json', 'folder': '/reports', 'size': 4096},
    }
    result = ReportExecutionSchema().load(raw)
    assert isinstance(result, ReportExecution)
    assert result.id == 1
    assert result.status == 'completed'
    assert isinstance(result.storage_details, SbomReportStorageDetails)


def test_requested_sbom_report_result_schema_load() -> None:
    raw = {
        'report_executions': [
            {
                'id': 1,
                'status': 'completed',
                'error_message': None,
                'status_message': 'Done',
                'storage_details': {'path': '/r/sbom.json', 'folder': '/r', 'size': 1024},
            },
            {
                'id': 2,
                'status': 'failed',
                'error_message': 'Timeout',
                'status_message': None,
                'storage_details': None,
            },
        ]
    }
    result = RequestedSbomReportResultSchema().load(raw)
    assert isinstance(result, SbomReport)
    assert len(result.report_executions) == 2
    assert result.report_executions[0].storage_details.path == '/r/sbom.json'
    assert result.report_executions[1].error_message == 'Timeout'
    assert result.report_executions[1].storage_details is None


# --- UserAgentOptionScheme ---


def test_user_agent_option_schema_load() -> None:
    raw = {
        'app_name': 'vscode_extension',
        'app_version': '0.2.3',
        'env_name': 'Visual Studio Code',
        'env_version': '1.78.2',
    }
    result = UserAgentOptionScheme().load(raw)
    assert isinstance(result, UserAgentOption)
    assert result.app_name == 'vscode_extension'
    assert 'vscode_extension' in result.user_agent_suffix
    assert 'AppVersion: 0.2.3' in result.user_agent_suffix


# --- MemberSchema / RequestedMemberDetailsResultSchema ---


def test_member_schema_load() -> None:
    raw = {'external_id': 'user-ext-123'}
    result = MemberSchema().load(raw)
    assert isinstance(result, Member)
    assert result.external_id == 'user-ext-123'


def test_requested_member_details_schema_load() -> None:
    raw = {
        'items': [{'external_id': 'u1'}, {'external_id': 'u2'}],
        'page_size': 50,
        'next_page_token': 'token-abc',
    }
    result = RequestedMemberDetailsResultSchema().load(raw)
    assert isinstance(result, MemberDetails)
    assert len(result.items) == 2
    assert result.page_size == 50
    assert result.next_page_token == 'token-abc'


def test_requested_member_details_schema_load_null_token() -> None:
    raw = {
        'items': [],
        'page_size': 50,
        'next_page_token': None,
    }
    result = RequestedMemberDetailsResultSchema().load(raw)
    assert result.next_page_token is None


# --- ClassificationDataSchema / DetectionRuleSchema ---


def test_classification_data_schema_load() -> None:
    raw = {'severity': 'high'}
    result = ClassificationDataSchema().load(raw)
    assert isinstance(result, ClassificationData)
    assert result.severity == 'high'


def test_detection_rule_schema_load() -> None:
    raw = {
        'classification_data': [{'severity': 'high'}, {'severity': 'medium'}],
        'detection_rule_id': 'rule-123',
        'custom_remediation_guidelines': 'Rotate the key',
        'remediation_guidelines': 'See docs',
        'description': 'Exposed API key',
        'policy_name': 'secrets-policy',
        'display_name': 'API Key Exposure',
    }
    result = DetectionRuleSchema().load(raw)
    assert isinstance(result, DetectionRule)
    assert len(result.classification_data) == 2
    assert result.classification_data[0].severity == 'high'
    assert result.detection_rule_id == 'rule-123'
    assert result.custom_remediation_guidelines == 'Rotate the key'


def test_detection_rule_schema_load_optional_nulls() -> None:
    raw = {
        'classification_data': [{'severity': 'low'}],
        'detection_rule_id': 'rule-456',
        'custom_remediation_guidelines': None,
        'remediation_guidelines': None,
        'description': None,
        'policy_name': None,
        'display_name': None,
    }
    result = DetectionRuleSchema().load(raw)
    assert result.custom_remediation_guidelines is None
    assert result.display_name is None


# --- ScanResultsSyncFlowSchema ---


def test_scan_results_sync_flow_schema_load() -> None:
    raw = {
        'id': 'sync-123',
        'detection_messages': [{'msg': 'found secret'}, {'msg': 'found vuln'}],
    }
    result = ScanResultsSyncFlowSchema().load(raw)
    assert isinstance(result, ScanResultsSyncFlow)
    assert result.id == 'sync-123'
    assert len(result.detection_messages) == 2


# --- SupportedModulesPreferencesSchema ---


def test_supported_modules_preferences_schema_load() -> None:
    raw = {
        'secret_scanning': True,
        'leak_scanning': True,
        'iac_scanning': False,
        'sca_scanning': True,
        'ci_cd_scanning': False,
        'sast_scanning': True,
        'container_scanning': False,
        'access_review': True,
        'asoc': False,
        'cimon': True,
        'ai_machine_learning': True,
        'ai_large_language_model': False,
    }
    result = SupportedModulesPreferencesSchema().load(raw)
    assert isinstance(result, SupportedModulesPreferences)
    assert result.secret_scanning is True
    assert result.iac_scanning is False
    assert result.ai_large_language_model is False


# --- ScanConfigurationSchema ---


def test_scan_configuration_schema_load() -> None:
    raw = {
        'scannable_extensions': ['.py', '.js', '.ts'],
        'is_cycode_ignore_allowed': True,
    }
    result = ScanConfigurationSchema().load(raw)
    assert isinstance(result, ScanConfiguration)
    assert result.scannable_extensions == ['.py', '.js', '.ts']
    assert result.is_cycode_ignore_allowed is True


def test_scan_configuration_schema_load_defaults() -> None:
    raw = {
        'scannable_extensions': None,
    }
    result = ScanConfigurationSchema().load(raw)
    assert result.scannable_extensions is None
    assert result.is_cycode_ignore_allowed is True  # load_default=True
