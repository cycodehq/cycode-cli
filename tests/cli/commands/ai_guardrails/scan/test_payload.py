from uuid import UUID

from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload


def test_hook_event_id_is_a_uuid() -> None:
    payload = AIHookPayload(event_name='Prompt')

    # Round-trips through UUID, so ai-security-manager can store it as the hook event's primary key
    assert UUID(payload.hook_event_id)


def test_hook_event_id_is_unique_per_payload() -> None:
    """One payload is one hook event. Sharing an id across events is what generation ids already do wrong."""
    first = AIHookPayload(event_name='Prompt', generation_id='same-gen')
    second = AIHookPayload(event_name='Prompt', generation_id='same-gen')

    assert first.hook_event_id != second.hook_event_id


def test_hook_event_id_survives_an_explicit_value() -> None:
    payload = AIHookPayload(event_name='Prompt', hook_event_id='fixed-id')

    assert payload.hook_event_id == 'fixed-id'
