import requests
from requests import Response
from typing import Optional


class HttpClient:
    def __init__(self, token: Optional[str] = None, timeout: int = 10, verify_ssl: bool = True):
        self.token = token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"Bearer {token}"})

    def get(self, url: str, headers: Optional[dict] = None, **kwargs) -> Response:
        return self.session.get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl, **kwargs)

    def post(self, url: str, json: Optional[dict] = None, headers: Optional[dict] = None, **kwargs) -> Response:
        return self.session.post(url, json=json, headers=headers, timeout=self.timeout, verify=self.verify_ssl, **kwargs)

    def request_without_auth(self, method: str, url: str, **kwargs) -> Response:
        """Send a request explicitly without the Authorization header."""
        session = requests.Session()
        return session.request(method, url, timeout=self.timeout, verify=self.verify_ssl, **kwargs)
