import sys

from cycode import config
from cycode.cli import consts
from cycode.logger import get_logger

logger = get_logger('Trust Store')

# truststore requires Python 3.10+, so on 3.9 we keep the certifi-based verification
_MIN_PYTHON_VERSION = (3, 10)

_installed = False


def is_installed() -> bool:
    """Whether the OS trust store has been injected into the TLS stack."""
    return _installed


def install() -> bool:
    """Make every TLS connection verify against the machine's trust store.

    `truststore.inject_into_ssl()` patches `ssl.SSLContext` process-wide, so this covers all HTTPS
    traffic (the shared session, the presigned S3 upload, the version check) without touching call
    sites. Certificates from `REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` keep working: requests still loads
    them, and truststore treats them as additional trust anchors on top of the OS store.

    Idempotent. Never raises: on any failure we fall back to certifi rather than breaking the CLI.
    """
    global _installed

    if _installed:
        return True

    if config.get_val_as_bool(consts.DISABLE_TRUSTSTORE_ENV_VAR_NAME):
        logger.debug('OS trust store disabled by env var, using the bundled CA store (certifi)')
        return False

    if sys.version_info < _MIN_PYTHON_VERSION:
        logger.debug(
            'OS trust store requires Python %s+, using the bundled CA store (certifi). Current version: %s',
            '.'.join(map(str, _MIN_PYTHON_VERSION)),
            '.'.join(map(str, sys.version_info[:3])),
        )
        return False

    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception as e:
        logger.debug('Failed to use the OS trust store, using the bundled CA store (certifi). %s', e)
        return False

    logger.debug('Using the OS trust store for TLS verification')
    _installed = True
    return True
