"""Module tests."""

from __future__ import annotations

from sbfleet.health import HEALTHY, UNHEALTHY, _http_probe


def test_http_401_not_healthy_by_default(monkeypatch) -> None:
    import urllib.error

    class Opener:
        def open(self, req, timeout=None):  # noqa: ANN001
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", hdrs=None, fp=None)

    monkeypatch.setattr("urllib.request.build_opener", lambda *a, **k: Opener())
    result = _http_probe("http://127.0.0.1:9/x", expect_status={200})
    assert result.status == UNHEALTHY


def test_http_200_healthy(monkeypatch) -> None:
    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"ok"

    class Opener:
        def open(self, req, timeout=None):  # noqa: ANN001
            return Resp()

    monkeypatch.setattr("urllib.request.build_opener", lambda *a, **k: Opener())
    result = _http_probe("http://127.0.0.1:9/x", expect_status={200})
    assert result.status == HEALTHY
