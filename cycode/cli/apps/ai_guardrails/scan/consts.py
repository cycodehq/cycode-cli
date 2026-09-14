"""
Constants and default configuration for AI guardrails.

Enforcement (which guardrails run, in which mode, over which paths) is platform-owned and
resolved per scan; see scan/guardrail_config.py. What is left here is the operational knobs
a local file may override - user-level ~/.cycode/ai-guardrails.yaml, then repo-level
<workspace>/.cycode/ai-guardrails.yaml.
"""

# Policy file name
POLICY_FILE_NAME = 'ai-guardrails.yaml'

# Sensitive-path globs used until the platform's own list is cached (cold start, or a tenant
# that never customized them). Not a local knob: apply_platform_config always overwrites it.
DEFAULT_SENSITIVE_PATH_GLOBS = [
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
]

# Default policy configuration: operational knobs only.
DEFAULT_POLICY = {
    'version': 1,
    'fail_open': True,  # allow if scan fails/timeouts
    'secrets': {
        'scan_type': 'secret',
        'timeout_ms': 30000,
        'max_bytes': 200000,
    },
}
