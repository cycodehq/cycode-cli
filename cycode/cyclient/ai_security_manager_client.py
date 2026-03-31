"""Client for AI Security Manager service."""

from typing import TYPE_CHECKING, Optional

from cycode.cli.exceptions.custom_exceptions import HttpUnauthorizedError
from cycode.cyclient.cycode_client_base import CycodeClientBase
from cycode.cyclient.logger import logger

if TYPE_CHECKING:
    from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
    from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType, AIHookOutcome, BlockReason
    from cycode.cyclient.ai_security_manager_service_config import AISecurityManagerServiceConfigBase


class AISecurityManagerClient:
    """Client for interacting with AI Security Manager service."""

    _CONVERSATIONS_PATH = 'v4/ai-security/interactions/conversations'
    _EVENTS_PATH = 'v4/ai-security/interactions/events'

    def __init__(self, client: CycodeClientBase, service_config: 'AISecurityManagerServiceConfigBase') -> None:
        self.client = client
        self.service_config = service_config

    def _build_endpoint_path(self, path: str) -> str:
        """Build the full endpoint path including service name/port."""
        service_name = self.service_config.get_service_name()
        if service_name:
            return f'{service_name}/{path}'
        return path

    def create_conversation(self, payload: 'AIHookPayload') -> Optional[str]:
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
        scan_id: Optional[str] = None,
        block_reason: Optional['BlockReason'] = None,
        error_message: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> None:
        """Create an AI hook event from hook payload."""
        conversation_id = payload.conversation_id
        if not conversation_id:
            logger.debug('No conversation ID available, skipping event creation')
            return

        body = {
            'conversation_id': conversation_id,
            'event_type': event_type,
            'outcome': outcome,
            'generation_id': payload.generation_id,
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
