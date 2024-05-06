import datetime
import time

from fastapi_jwt import AuthlibJWTBackend, PythonJoseJWTBackend

_time = time.time
_now = datetime.datetime.now
_utcnow = datetime.datetime.utcnow


def create_datetime_mock(**timedelta_kwargs):
    class _FakeDateTime(datetime.datetime):  # pragma: no cover
        @staticmethod
        def now(**kwargs):
            return _now() + datetime.timedelta(**timedelta_kwargs)

        @staticmethod
        def utcnow(**kwargs):
            return _utcnow() + datetime.timedelta(**timedelta_kwargs)

    return _FakeDateTime


def create_time_time_mock(**kwargs):
    def _fake_time_time():
        return _time() + datetime.timedelta(**kwargs).total_seconds()

    return _fake_time_time


def mock_now_for_backend(mocker, jwt_backend, **kwargs):
    if jwt_backend is AuthlibJWTBackend:
        mocker.patch("authlib.jose.rfc7519.claims.time.time", create_time_time_mock(**kwargs))
    elif jwt_backend is PythonJoseJWTBackend:
        mocker.patch("jose.jwt.datetime", create_datetime_mock(**kwargs))
    else:
        raise Exception("Invalid Backend")
