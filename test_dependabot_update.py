import types
import builtins
import json
from io import StringIO
from contextlib import redirect_stdout

import main

class DummyResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or json.dumps(self._payload)
    def json(self):
        return self._payload

class DummyRepo:
    def __init__(self, name):
        self.name = name
        self.full_name = f"example/{name}"

# Helpers to build encrypted value without hitting real libs

def test_update_dependabot_secret_when_exists(monkeypatch):
    """Simulate update where secret exists: expect delete then put (201/204) path."""
    calls = {"get":0, "delete":0, "put":0}

    def fake_get(url, headers=None):
        calls["get"] += 1
        if url.endswith('/dependabot/secrets'):
            return DummyResponse(200, {"secrets": [{"name": "SECRET_ONE"}]})
        if url.endswith('/dependabot/secrets/public-key'):
            # 32 raw bytes -> base64 ("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
            return DummyResponse(200, {"key_id": "kid123", "key": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="})
        raise AssertionError(f"Unexpected GET {url}")

    def fake_delete(url, headers=None):
        calls["delete"] += 1
        return DummyResponse(204)

    def fake_put(url, headers=None, data=None):
        calls["put"] += 1
        body = json.loads(data)
        assert body["key_id"] == "kid123"
        assert "encrypted_value" in body
        return DummyResponse(204)

    monkeypatch.setattr(main.requests, 'get', fake_get)
    monkeypatch.setattr(main.requests, 'delete', fake_delete)
    monkeypatch.setattr(main.requests, 'put', fake_put)

    out = StringIO()
    with redirect_stdout(out):
        main.update_dependabot_secret('tok123', DummyRepo('repo1'), 'SECRET_ONE', 'NEWVAL', 'example')

    # Assertions
    assert calls == {"get":2, "delete":1, "put":1}
    printed = out.getvalue()
    assert 'Delete (before update) Response Code: 204' in printed
    assert 'dependabot Secret "SECRET_ONE" updated in repo1' in printed


def test_update_dependabot_secret_when_missing(monkeypatch):
    """Simulate update where secret missing: expect get then put (create) path, no delete."""
    calls = {"get":0, "delete":0, "put":0}

    def fake_get(url, headers=None):
        calls["get"] += 1
        if url.endswith('/dependabot/secrets'):
            return DummyResponse(200, {"secrets": []})
        if url.endswith('/dependabot/secrets/public-key'):
            return DummyResponse(200, {"key_id": "kid456", "key": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="})
        raise AssertionError(f"Unexpected GET {url}")

    def fake_delete(url, headers=None):
        calls["delete"] += 1
        return DummyResponse(404)

    def fake_put(url, headers=None, data=None):
        calls["put"] += 1
        body = json.loads(data)
        assert body["key_id"] == "kid456"
        assert "encrypted_value" in body
        return DummyResponse(201)

    monkeypatch.setattr(main.requests, 'get', fake_get)
    monkeypatch.setattr(main.requests, 'delete', fake_delete)
    monkeypatch.setattr(main.requests, 'put', fake_put)

    out = StringIO()
    with redirect_stdout(out):
        main.update_dependabot_secret('tok123', DummyRepo('repo2'), 'SECRET_TWO', 'NEWVAL', 'example')

    assert calls == {"get":2, "delete":0, "put":1}
    printed = out.getvalue()
    assert 'Create (update) Response Code: 201' in printed
    assert 'dependabot Secret "SECRET_TWO" updated in repo2' in printed
