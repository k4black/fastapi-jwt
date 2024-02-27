from fastapi import HTTPException
from typing import Any, Dict, Optional
from starlette.status import HTTP_401_UNAUTHORIZED

from authlib.jose import JsonWebSignature, JsonWebToken
from authlib.jose.errors import (
    DecodeError, ExpiredTokenError, InvalidClaimError, InvalidTokenError
)
from .abstract_backend import AbstractJWTBackend


class AuthlibJWTBackend(AbstractJWTBackend):

    def __init__(self, algorithm) -> None:
        self.algorithm = algorithm if algorithm is not None else self.default_algorithm
        # from https://github.com/lepture/authlib/blob/85f9ff/authlib/jose/__init__.py#L45
        valid_algorithms = JsonWebSignature.ALGORITHMS_REGISTRY.keys()
        assert (
            self.algorithm in valid_algorithms
        ), f"{self.algorithm} algorithm is not supported by authlib"
        self.jwt = JsonWebToken(algorithms=[self.algorithm])

    @property
    def default_algorithm(self) -> str:
        return "HS256"

    def encode(self, to_encode, secret_key) -> str:
        token = self.jwt.encode(header={"alg": self.algorithm}, payload=to_encode, key=secret_key)
        return token.decode()  # convert to string

    def decode(self, token, secret_key, auto_error) -> Optional[Dict[str, Any]]:
        try:
            payload = self.jwt.decode(token, secret_key)
            payload.validate(leeway=10)
            return dict(payload)
        except ExpiredTokenError as e:  # type: ignore[attr-defined]
            if auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail=f"Token time expired: {e}"
                )
            else:
                return None
        except (InvalidClaimError,
                InvalidTokenError,
                DecodeError) as e:  # type: ignore[attr-defined]
            if auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail=f"Wrong token: {e}"
                )
            else:
                return None
