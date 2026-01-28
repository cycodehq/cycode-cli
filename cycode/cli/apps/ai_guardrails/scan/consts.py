"""
Constants and default configuration for AI guardrails.

These defaults can be overridden by:
1. User-level config: ~/.cycode/ai-guardrails.yaml
2. Repo-level config: <workspace>/.cycode/ai-guardrails.yaml
"""

# Policy file name
POLICY_FILE_NAME = 'ai-guardrails.yaml'

# Default policy configuration
DEFAULT_POLICY = {
    'version': 1,
    'mode': 'block',  # block | warn
    'fail_open': True,  # allow if scan fails/timeouts
    'secrets': {
        'scan_type': 'secret',
        'timeout_ms': 30000,
        'max_bytes': 200000,
    },
    'prompt': {
        'enabled': True,
        'action': 'block',
    },
    'file_read': {
        'enabled': True,
        'action': 'block',
        'deny_globs': [
            '.env',
            '.env.*',
            '*.pem',
            '*.p12',
            '*.key',
            '.aws/**',
            '.ssh/**',
            '*kubeconfig*',
            '.npmrc',
            '.netrc',
        ],
        'scan_content': True,
    },
    'mcp': {
        'enabled': True,
        'action': 'block',
        'scan_arguments': True,
    },
}
