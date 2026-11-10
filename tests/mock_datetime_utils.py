import datetime
import time

_time = time.time


def create_time_time_mock(**kwargs):
    def _fake_time_time():
        return _time() + datetime.timedelta(**kwargs).total_seconds()

    return _fake_time_time


def mock_now(mocker, **kwargs):
    mocker.patch("joserfc._rfc7519.claims.time.time", create_time_time_mock(**kwargs))
