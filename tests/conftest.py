from typing import Type

import pytest

from fastapi_jwt.jwt_backends import AbstractJWTBackend, AuthlibJWTBackend, PythonJoseJWTBackend


@pytest.fixture(params=[PythonJoseJWTBackend, AuthlibJWTBackend])
def jwt_backend(request: pytest.FixtureRequest) -> Type[AbstractJWTBackend]:
    return request.param
