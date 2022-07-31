from cli.utils.string_utils import generate_random_string, hash_string_to_sha256


class AuthManager:

    CODE_VERIFIER_LENGTH = 100

    def generate_pkce_code_pair(self) -> (str, str):
        code_verifier = generate_random_string(self.CODE_VERIFIER_LENGTH)
        code_challenge = hash_string_to_sha256(code_verifier)
        return code_challenge, code_verifier
