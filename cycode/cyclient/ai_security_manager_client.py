"""Client for AI Security Manager service."""

from typing import TYPE_CHECKING

from cycode.cli.exceptions.custom_exceptions import HttpUnauthorizedError
from cycode.cyclient.cycode_client_base import CycodeClientBase
from cycode.cyclient.logger import logger
from cycode.cyclient.models import SessionContextResponse, SessionContextResponseSchema

if TYPE_CHECKING:
    from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
    from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType, AIHookOutcome, BlockReason
    from cycode.cyclient.ai_security_manager_service_config import AISecurityManagerServiceConfigBase


class AISecurityManagerClient:
    """Client for interacting with AI Security Manager service."""

    _CONVERSATIONS_PATH = 'v4/ai-security/interactions/conversations'
    _EVENTS_PATH = 'v4/ai-security/interactions/events'
    _SESSION_CONTEXT_PATH = 'v4/ai-security/interactions/session-context'
    _RESOLVED_GUARDRAILS_PATH = 'v4/ai-security/guardrails/resolved'

    def __init__(self, client: CycodeClientBase, service_config: 'AISecurityManagerServiceConfigBase') -> None:
        self.client = client
        self.service_config = service_config

    def _build_endpoint_path(self, path: str) -> str:
        """Build the full endpoint path including service name/port."""
        service_name = self.service_config.get_service_name()
        if service_name:
            return f'{service_name}/{path}'
        return path

    def create_conversation(self, payload: 'AIHookPayload') -> str | None:
        """Creates an AI conversation from hook payload."""
        conversation_id = payload.conversation_id
        if not conversation_id:
            return None

        body = {
            'id': conversation_id,
            'ide_user_email': payload.ide_user_email,
            'model': payload.model,
            'ide_provider': payload.ide_provider,
            'ide_version': payload.ide_version,
            'source': payload.source,
        }

        try:
            self.client.post(self._build_endpoint_path(self._CONVERSATIONS_PATH), body=body)
        except HttpUnauthorizedError:
            # Authentication error - re-raise so prompt_command can catch it
            raise
        except Exception as e:
            logger.debug('Failed to create conversation', exc_info=e)
            # Don't fail the hook if tracking fails (non-auth errors)

        return conversation_id

    def create_event(
        self,
        payload: 'AIHookPayload',
        event_type: 'AiHookEventType',
        outcome: 'AIHookOutcome',
        scan_id: str | None = None,
        block_reason: 'BlockReason | None' = None,
        error_message: str | None = None,
        file_path: str | None = None,
    ) -> None:
        """Create an AI hook event from hook payload."""
        conversation_id = payload.conversation_id
        if not conversation_id:
            logger.debug('No conversation ID available, skipping event creation')
            return

        body = {
            'id': payload.hook_event_id,
            'conversation_id': conversation_id,
            'event_type': event_type,
            'outcome': outcome,
            'generation_id': payload.generation_id,
            'model': payload.model,
            'block_reason': block_reason,
            'cli_scan_id': scan_id,
            'mcp_server_name': payload.mcp_server_name,
            'mcp_tool_name': payload.mcp_tool_name,
            'error_message': error_message,
            'file_path': file_path,
        }

        try:
            self.client.post(self._build_endpoint_path(self._EVENTS_PATH), body=body)
        except Exception as e:
            logger.debug('Failed to create AI hook event', exc_info=e)
            # Don't fail the hook if tracking fails

    def get_resolved_guardrails(self) -> dict | None:
        """Fetch the tenant's resolved guardrail config (per-agent modes + sensitive-path globs)."""
        try:
            response = self.client.get(self._build_endpoint_path(self._RESOLVED_GUARDRAILS_PATH))
            return response.json()
        except Exception as e:
            logger.debug('Failed to fetch resolved guardrail config', exc_info=e)
            return None

    def report_session_context(
        self,
        hostname: str | None = None,
        platform_name: str | None = None,
        os_version: str | None = None,
        serial_number: str | None = None,
        last_login_user: str | None = None,
        config_files: list[dict] | None = None,
        enabled_plugins: dict | None = None,
        skill_files: list[dict] | None = None,
        user_email: str | None = None,
    ) -> SessionContextResponse | None:
        """Report session context to the backend. Returns None when the report was not accepted."""
        body: dict = {
            'hostname': hostname,
            'platform_name': platform_name,
            'os_version': os_version,
            'serial_number': serial_number,
            'last_login_user': last_login_user,
            'user_email': user_email,
            'config_files': config_files,
            'enabled_plugins': enabled_plugins,
            'skill_files': skill_files,
        }

        try:
            response = self.client.post(self._build_endpoint_path(self._SESSION_CONTEXT_PATH), body=body)
        except Exception as e:
            logger.debug('Failed to report session context', exc_info=e)
            # Don't fail the session if reporting fails
            return None

        try:
            return SessionContextResponseSchema().load(response.json())
        except Exception as e:
            logger.debug('Failed to parse the session context response', exc_info=e)
            return SessionContextResponse()
