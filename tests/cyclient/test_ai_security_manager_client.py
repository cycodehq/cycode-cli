from unittest.mock import MagicMock

from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType, AIHookOutcome
from cycode.cyclient.ai_security_manager_client import AISecurityManagerClient


def _build_client() -> tuple[AISecurityManagerClient, MagicMock]:
    http_client = MagicMock()
    service_config = MagicMock()
    service_config.get_service_name.return_value = None

    return AISecurityManagerClient(http_client, service_config), http_client


def _posted_body(http_client: MagicMock) -> dict:
    return http_client.post.call_args.kwargs['body']


def test_create_event_reports_the_payload_hook_event_id_as_the_event_id() -> None:
    """The CLI owns the id so the guardrail detection, reported separately, can name this exact event."""
    client, http_client = _build_client()
    payload = AIHookPayload(event_name='Prompt', conversation_id='conv-1', generation_id='gen-1')

    client.create_event(payload, AiHookEventType.PROMPT, AIHookOutcome.ALLOWED)

    assert _posted_body(http_client)['id'] == payload.hook_event_id


def test_create_event_reports_a_distinct_id_per_hook_event() -> None:
    client, http_client = _build_client()
    conversation_id = 'conv-1'
    # Two hooks of the same prompt: the generation id is shared, the hook event id must not be
    first = AIHookPayload(event_name='Prompt', conversation_id=conversation_id, generation_id='gen-1')
    second = AIHookPayload(event_name='FileRead', conversation_id=conversation_id, generation_id='gen-1')

    client.create_event(first, AiHookEventType.PROMPT, AIHookOutcome.ALLOWED)
    client.create_event(second, AiHookEventType.FILE_READ, AIHookOutcome.ALLOWED)

    reported_ids = [call.kwargs['body']['id'] for call in http_client.post.call_args_list]
    assert reported_ids == [first.hook_event_id, second.hook_event_id]
    assert len(set(reported_ids)) == 2


def test_create_event_without_a_conversation_posts_nothing() -> None:
    client, http_client = _build_client()

    client.create_event(AIHookPayload(event_name='Prompt'), AiHookEventType.PROMPT, AIHookOutcome.ALLOWED)

    http_client.post.assert_not_called()
