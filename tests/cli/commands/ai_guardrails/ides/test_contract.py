"""IDE contract tests, parameterized over the entire IDES registry.

Every concrete IDE registered in `ides/__init__.py` must satisfy these
assertions. Adding a new IDE without updating these tests means the new
IDE inherits the same baseline guarantees (and fails fast if it doesn't).
"""

from pathlib import Path

import pytest

from cycode.cli.apps.ai_guardrails.ides import IDES
from cycode.cli.apps.ai_guardrails.ides.base import IDE, DecisionAction, HookDecision
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType


def test_ides_registry_is_non_empty() -> None:
    """Sanity check: the refactor isn't useful with zero registered IDEs."""
    assert len(IDES) >= 1


@pytest.fixture(params=sorted(IDES), ids=sorted(IDES))
def ide(request: pytest.FixtureRequest) -> IDE:
    return IDES[request.param]


def test_identity_attributes_set(ide: IDE) -> None:
    """Every IDE must declare name, display_name, hook_events."""
    assert isinstance(ide.name, str)
    assert ide.name
    assert isinstance(ide.display_name, str)
    assert ide.display_name
    assert isinstance(ide.hook_events, list)
    assert ide.hook_events


def test_registry_key_matches_name(ide: IDE) -> None:
    """The registry key must equal the IDE's own `name` attribute."""
    assert IDES[ide.name] is ide


def test_settings_path_user_scope(ide: IDE) -> None:
    """User scope must return a Path (without requiring a repo_path)."""
    path = ide.settings_path('user')
    assert isinstance(path, Path)


def test_settings_path_repo_scope(ide: IDE, tmp_path: Path) -> None:
    """Repo scope path must live under the supplied repo directory."""
    path = ide.settings_path('repo', tmp_path)
    assert isinstance(path, Path)
    assert str(path).startswith(str(tmp_path))


def test_render_hooks_config_has_hooks_key(ide: IDE) -> None:
    """All IDEs share the outer `{"hooks": ...}` wrapper so hooks_manager can merge."""
    rendered = ide.render_hooks_config()
    assert isinstance(rendered, dict)
    assert 'hooks' in rendered
    assert isinstance(rendered['hooks'], dict)


def test_render_hooks_config_async_changes_output(ide: IDE) -> None:
    """async_mode must influence the rendered output."""
    assert ide.render_hooks_config(async_mode=False) != ide.render_hooks_config(async_mode=True)


def test_matches_payload_rejects_empty(ide: IDE) -> None:
    """Empty payloads can't legitimately come from any IDE."""
    assert ide.matches_payload({}) is False
    assert ide.matches_payload({'hook_event_name': ''}) is False


def test_matches_payload_rejects_unrelated_event_names(ide: IDE) -> None:
    """Unknown event names from other IDEs must be ignored to avoid double-processing."""
    assert ide.matches_payload({'hook_event_name': 'completely-fabricated-event'}) is False


@pytest.mark.parametrize('event_type', list(AiHookEventType))
def test_build_hook_response_allow_returns_dict(ide: IDE, event_type: AiHookEventType) -> None:
    """ALLOW for every canonical event type yields a serializable dict."""
    response = ide.build_hook_response(HookDecision.allow(event_type))
    assert isinstance(response, dict)


@pytest.mark.parametrize('event_type', list(AiHookEventType))
def test_build_hook_response_deny_carries_message(ide: IDE, event_type: AiHookEventType) -> None:
    """DENY must surface the user message somewhere in the response (any key)."""
    response = ide.build_hook_response(HookDecision.deny(event_type, 'A unique deny reason', 'agent msg'))
    # Search recursively — IDEs use different key names for the message.
    assert _contains_value(response, 'A unique deny reason'), response


@pytest.mark.parametrize('event_type', [AiHookEventType.FILE_READ, AiHookEventType.MCP_EXECUTION])
def test_build_hook_response_ask_carries_message(ide: IDE, event_type: AiHookEventType) -> None:
    """ASK is meaningful for permission events. Message must propagate."""
    response = ide.build_hook_response(HookDecision.ask(event_type, 'A unique ask reason'))
    assert _contains_value(response, 'A unique ask reason'), response


def test_build_session_payload_tags_ide(ide: IDE) -> None:
    """Session payload must identify the originating IDE."""
    session = ide.build_session_payload({})
    assert session.ide_provider == ide.name


def test_get_session_context_returns_pair(ide: IDE) -> None:
    """Session context must be a ``(global_config_file, plugins)`` pair.

    ``global_config_file`` is ``None`` or a ``{"path", "content"}`` dict; ``plugins`` is a dict.
    """
    global_config_file, plugins = ide.get_session_context()
    assert global_config_file is None or isinstance(global_config_file, dict)
    assert isinstance(plugins, dict)


# HookDecision helpers


def test_hook_decision_helpers() -> None:
    allow = HookDecision.allow(AiHookEventType.PROMPT)
    assert allow.action == DecisionAction.ALLOW
    assert allow.event_type == AiHookEventType.PROMPT
    assert allow.user_message is None

    deny = HookDecision.deny(AiHookEventType.FILE_READ, 'why', 'agent')
    assert deny.action == DecisionAction.DENY
    assert deny.user_message == 'why'
    assert deny.agent_message == 'agent'

    ask = HookDecision.ask(AiHookEventType.MCP_EXECUTION, 'maybe?')
    assert ask.action == DecisionAction.ASK
    assert ask.user_message == 'maybe?'


def _contains_value(obj: object, needle: str) -> bool:
    """Recursively search a nested dict/list for a string value."""
    if isinstance(obj, str):
        return needle in obj
    if isinstance(obj, dict):
        return any(_contains_value(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_value(v, needle) for v in obj)
    return False
