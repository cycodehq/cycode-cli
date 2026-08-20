import sys

from cycode import config
from cycode.cli import consts
from cycode.logger import get_logger

logger = get_logger('Trust Store')

# truststore requires Python 3.10+, so on 3.9 the OS trust store is unavailable
_MIN_PYTHON_VERSION = (3, 10)

_installed = False


def is_supported() -> bool:
    return sys.version_info >= _MIN_PYTHON_VERSION


def is_enabled() -> bool:
    return config.get_val_as_bool(consts.ENABLE_TRUSTSTORE_ENV_VAR_NAME)


def is_installed() -> bool:
    """Whether the OS trust store has been injected into the TLS stack."""
    return _installed


def install() -> bool:
    """Verify TLS against the machine's trust store.

    `truststore.inject_into_ssl()` patches `ssl.SSLContext` process-wide, so this covers all HTTPS
    traffic (the shared session, the presigned S3 upload, the version check) without touching call
    sites. Certificates from `REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` keep working: requests still loads
    them, and truststore treats them as additional trust anchors on top of the OS store.
    """
    global _installed

    if _installed:
        return True

    if not is_enabled():
        logger.debug(
            'OS trust store not enabled, using the bundled CA store (certifi). Set %s=1 to enable it',
            consts.ENABLE_TRUSTSTORE_ENV_VAR_NAME,
        )
        return False

    if not is_supported():
        logger.warning(
            'OS trust store requires Python %s+, using the bundled CA store (certifi). Current version: %s',
            '.'.join(map(str, _MIN_PYTHON_VERSION)),
            '.'.join(map(str, sys.version_info[:3])),
        )
        return False

    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception as e:
        logger.warning('Failed to use the OS trust store, falling back to the bundled CA store (certifi). %s', e)
        return False

    logger.debug('Using the OS trust store for TLS verification')
    _installed = True
    return True
