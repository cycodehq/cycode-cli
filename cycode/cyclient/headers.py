import platform
from typing import Optional
from uuid import uuid4

from cycode import __version__
from cycode.cli import consts
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.sentry import add_correlation_id_to_scope
from cycode.cyclient.logger import logger


def get_cli_user_agent() -> str:
    """Return base User-Agent of CLI.

    Example: CycodeCLI/0.2.3 (OS: Darwin; Arch: arm64; Python: 3.8.16; InstallID: *uuid4*)
    """
    version = __version__

    os = platform.system()
    arch = platform.machine()
    python_version = platform.python_version()

    install_id = ConfigurationManager().get_or_create_installation_id()

    return f'{consts.APP_NAME}/{version} (OS: {os}; Arch: {arch}; Python: {python_version}; InstallID: {install_id})'


class _CorrelationId:
    _id: Optional[str] = None

    def get_correlation_id(self) -> str:
        """Get correlation ID.

        Notes:
            Used across all requests to correlate logs and metrics.
            It doesn't depend on client instances.
            Lifetime is the same as the process.

        """
        if self._id is None:
            # example: 16fd2706-8baf-433b-82eb-8c7fada847da
            self._id = str(uuid4())
            logger.debug('Correlation ID: %s', self._id)

        add_correlation_id_to_scope(self._id)

        return self._id


get_correlation_id = _CorrelationId().get_correlation_id
