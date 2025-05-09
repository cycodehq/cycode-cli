import logging
from dataclasses import dataclass
from typing import Optional

import sentry_sdk
from sentry_sdk.integrations.atexit import AtexitIntegration
from sentry_sdk.integrations.dedupe import DedupeIntegration
from sentry_sdk.integrations.excepthook import ExcepthookIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber

from cycode import __version__
from cycode.cli import consts
from cycode.cli.logger import logger
from cycode.cli.utils.jwt_utils import get_user_and_tenant_ids_from_access_token
from cycode.cyclient.config import on_premise_installation

# when Sentry is blocked on the machine, we want to keep clean output without retries warnings
logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
logging.getLogger('sentry_sdk').setLevel(logging.ERROR)


@dataclass
class _SentrySession:
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    correlation_id: Optional[str] = None


_SENTRY_SESSION = _SentrySession()
_DENY_LIST = [*DEFAULT_DENYLIST, 'access_token']


def _get_sentry_release() -> str:
    return f'{consts.APP_NAME}@{__version__}'


def _get_sentry_local_release() -> str:
    return f'{consts.APP_NAME}@0.0.0'


_SENTRY_LOCAL_RELEASE = _get_sentry_local_release()
_SENTRY_DISABLED = on_premise_installation


def _before_sentry_event_send(event: dict, _: dict) -> Optional[dict]:
    if _SENTRY_DISABLED:
        # drop all events when Sentry is disabled
        return None

    if event.get('release') == _SENTRY_LOCAL_RELEASE:
        logger.debug('Dropping Sentry event due to local development setup')
        return None

    return event


def init_sentry() -> None:
    sentry_sdk.init(
        dsn=consts.SENTRY_DSN,
        debug=consts.SENTRY_DEBUG,
        release=_get_sentry_release(),
        server_name='',
        before_send=_before_sentry_event_send,
        sample_rate=consts.SENTRY_SAMPLE_RATE,
        send_default_pii=consts.SENTRY_SEND_DEFAULT_PII,
        include_local_variables=consts.SENTRY_INCLUDE_LOCAL_VARIABLES,
        max_request_body_size=consts.SENTRY_MAX_REQUEST_BODY_SIZE,
        event_scrubber=EventScrubber(denylist=_DENY_LIST, recursive=True),
        default_integrations=False,
        integrations=[
            AtexitIntegration(lambda _, __: None),  # disable output to stderr about pending events
            ExcepthookIntegration(),
            DedupeIntegration(),
            LoggingIntegration(),
        ],
    )


def setup_scope_from_access_token(access_token: Optional[str]) -> None:
    if not access_token:
        return

    user_id, tenant_id = get_user_and_tenant_ids_from_access_token(access_token)

    _SENTRY_SESSION.user_id = user_id
    _SENTRY_SESSION.tenant_id = tenant_id

    _setup_scope(user_id, tenant_id, _SENTRY_SESSION.correlation_id)


def add_correlation_id_to_scope(correlation_id: str) -> None:
    _setup_scope(_SENTRY_SESSION.user_id, _SENTRY_SESSION.tenant_id, correlation_id)


def _setup_scope(user_id: str, tenant_id: str, correlation_id: Optional[str] = None) -> None:
    scope = sentry_sdk.Scope.get_current_scope()
    sentry_sdk.set_tag('tenant_id', tenant_id)

    user = {'id': user_id, 'tenant_id': tenant_id}
    if correlation_id:
        user['correlation_id'] = correlation_id

    scope.set_user(user)


def capture_exception(exception: BaseException) -> None:
    sentry_sdk.capture_exception(exception)


def add_breadcrumb(message: str, category: str = 'cli') -> None:
    sentry_sdk.add_breadcrumb(category=category, message=message, level='info')
