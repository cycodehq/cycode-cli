from .client import CycodeClient


class AuthClient(CycodeClient):

    AUTH_CONTROLLER_PATH = 'api/v1/device-auth'

    def __init__(self, client_id: str = None, client_secret: str = None):
        super().__init__(client_id, client_secret)

    def start_session(self, code_challenge: str):
        path = f"/{self.AUTH_CONTROLLER_PATH}/start"
        body = {'code_challenge': code_challenge}
        response = self.post(url_path=path, body=body)
        return self.parse_scan_response(response)
