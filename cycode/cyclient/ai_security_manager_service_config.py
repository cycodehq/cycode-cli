"""Service configuration for AI Security Manager."""


class AISecurityManagerServiceConfigBase:
    """Base class for AI Security Manager service configuration."""

    def get_service_name(self) -> str:
        """Get the service name or port for URL construction.

        In dev mode, returns the port number.
        In production, returns the service name.
        """
        raise NotImplementedError


class DevAISecurityManagerServiceConfig(AISecurityManagerServiceConfigBase):
    """Dev configuration for AI Security Manager."""

    def get_service_name(self) -> str:
        return '5163/api'


class DefaultAISecurityManagerServiceConfig(AISecurityManagerServiceConfigBase):
    """Production configuration for AI Security Manager."""

    def get_service_name(self) -> str:
        return ''
