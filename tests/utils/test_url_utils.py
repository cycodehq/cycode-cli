from cycode.cli.utils.url_utils import sanitize_repository_url


def test_sanitize_repository_url_with_token() -> None:
    """Test that PAT tokens are removed from HTTPS URLs."""
    url = 'https://token@github.com/user/repo.git'
    expected = 'https://github.com/user/repo.git'
    assert sanitize_repository_url(url) == expected


def test_sanitize_repository_url_with_username_and_token() -> None:
    """Test that username and token are removed from HTTPS URLs."""
    url = 'https://user:token@github.com/user/repo.git'
    expected = 'https://github.com/user/repo.git'
    assert sanitize_repository_url(url) == expected


def test_sanitize_repository_url_with_port() -> None:
    """Test that URLs with ports are handled correctly."""
    url = 'https://token@github.com:443/user/repo.git'
    expected = 'https://github.com:443/user/repo.git'
    assert sanitize_repository_url(url) == expected


def test_sanitize_repository_url_ssh_format() -> None:
    """Test that SSH URLs are returned as-is (no credentials in URL format)."""
    url = 'git@github.com:user/repo.git'
    assert sanitize_repository_url(url) == url


def test_sanitize_repository_url_ssh_protocol() -> None:
    """Test that ssh:// URLs are returned as-is."""
    url = 'ssh://git@github.com/user/repo.git'
    assert sanitize_repository_url(url) == url


def test_sanitize_repository_url_no_credentials() -> None:
    """Test that URLs without credentials are returned unchanged."""
    url = 'https://github.com/user/repo.git'
    assert sanitize_repository_url(url) == url


def test_sanitize_repository_url_none() -> None:
    """Test that None input returns None."""
    assert sanitize_repository_url(None) is None


def test_sanitize_repository_url_empty_string() -> None:
    """Test that empty string is returned as-is."""
    assert sanitize_repository_url('') == ''


def test_sanitize_repository_url_gitlab() -> None:
    """Test that GitLab URLs are sanitized correctly."""
    url = 'https://oauth2:token@gitlab.com/user/repo.git'
    expected = 'https://gitlab.com/user/repo.git'
    assert sanitize_repository_url(url) == expected


def test_sanitize_repository_url_bitbucket() -> None:
    """Test that Bitbucket URLs are sanitized correctly."""
    url = 'https://x-token-auth:token@bitbucket.org/user/repo.git'
    expected = 'https://bitbucket.org/user/repo.git'
    assert sanitize_repository_url(url) == expected


def test_sanitize_repository_url_with_path_and_query() -> None:
    """Test that URLs with paths, query params, and fragments are preserved."""
    url = 'https://token@github.com/user/repo.git?ref=main#section'
    expected = 'https://github.com/user/repo.git?ref=main#section'
    assert sanitize_repository_url(url) == expected


def test_sanitize_repository_url_invalid_url() -> None:
    """Test that invalid URLs are returned as-is (graceful degradation)."""
    # This should not raise an exception, but return the original
    url = 'not-a-valid-url'
    result = sanitize_repository_url(url)
    # Should return original since parsing fails
    assert result == url
