from typing import Optional
from urllib.parse import urlparse, urlunparse

from cycode.logger import get_logger

logger = get_logger('URL Utils')


def sanitize_repository_url(url: Optional[str]) -> Optional[str]:
    """Remove credentials (username, password, tokens) from repository URL.

    This function sanitizes repository URLs to prevent sending PAT tokens or other
    credentials to the API. It handles both HTTP/HTTPS URLs with embedded credentials
    and SSH URLs (which are returned as-is since they don't contain credentials in the URL).

    Args:
        url: Repository URL that may contain credentials (e.g., https://token@github.com/user/repo.git)

    Returns:
        Sanitized URL without credentials (e.g., https://github.com/user/repo.git), or None if input is None

    Examples:
        >>> sanitize_repository_url('https://token@github.com/user/repo.git')
        'https://github.com/user/repo.git'
        >>> sanitize_repository_url('https://user:token@github.com/user/repo.git')
        'https://github.com/user/repo.git'
        >>> sanitize_repository_url('git@github.com:user/repo.git')
        'git@github.com:user/repo.git'
        >>> sanitize_repository_url(None)
        None
    """
    if not url:
        return url

    # Handle SSH URLs - no credentials to remove
    # ssh:// URLs have the format ssh://git@host/path
    if url.startswith('ssh://'):
        return url
    # git@host:path format (scp-style)
    if '@' in url and '://' not in url and url.startswith('git@'):
        return url

    try:
        parsed = urlparse(url)
        # Remove username and password from netloc
        # Reconstruct URL without credentials
        sanitized_netloc = parsed.hostname
        if parsed.port:
            sanitized_netloc = f'{sanitized_netloc}:{parsed.port}'

        return urlunparse(
            (
                parsed.scheme,
                sanitized_netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
    except Exception as e:
        logger.debug('Failed to sanitize repository URL, returning original, %s', {'url': url, 'error': str(e)})
        # If parsing fails, return original URL to avoid breaking functionality
        return url
