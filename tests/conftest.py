from typing import Type

import pytest

from fastapi_jwt.jwt_backends import AbstractJWTBackend, AuthlibJWTBackend


@pytest.fixture
def jwt_backend() -> Type[AbstractJWTBackend]:
    return AuthlibJWTBackend
