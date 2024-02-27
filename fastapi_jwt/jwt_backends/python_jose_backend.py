from fastapi import HTTPException
from typing import Any, Dict, Optional
from starlette.status import HTTP_401_UNAUTHORIZED

from jose import jwt

from .abstract_backend import AbstractJWTBackend


class PythonJoseJWTBackend(AbstractJWTBackend):

    def __init__(self, algorithm) -> None:
        self.algorithm = algorithm if algorithm is not None else self.default_algorithm
        assert (
            hasattr(jwt.ALGORITHMS, self.algorithm) is True  # type: ignore[attr-defined]
        ), f"{algorithm} algorithm is not supported by python-jose library"

    @property
    def default_algorithm(self) -> str:
        return jwt.ALGORITHMS.HS256

    def encode(self, to_encode, secret_key) -> str:
        return jwt.encode(to_encode, secret_key, algorithm=self.algorithm)

    def decode(self, token, secret_key, auto_error) -> Optional[Dict[str, Any]]:
        try:
            payload: Dict[str, Any] = jwt.decode(
                token,
                secret_key,
                algorithms=[self.algorithm],
                options={"leeway": 10},
            )
            return payload
        except jwt.ExpiredSignatureError as e:  # type: ignore[attr-defined]
            if auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail=f"Token time expired: {e}"
                )
            else:
                return None
        except jwt.JWTError as e:  # type: ignore[attr-defined]
            if auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail=f"Wrong token: {e}"
                )
            else:
                return None
