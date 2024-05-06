from typing import Any, Dict, Optional

from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED

try:
    from jose import jwt
except ImportError:
    jwt = None  # type: ignore

from .abstract_backend import AbstractJWTBackend


class PythonJoseJWTBackend(AbstractJWTBackend):
    def __init__(self, algorithm: Optional[str] = None) -> None:
        assert jwt is not None, "To use PythonJoseJWTBackend, you need to install python-jose"

        self._algorithm = algorithm or self.default_algorithm
        assert (
            hasattr(jwt.ALGORITHMS, self._algorithm) is True  # type: ignore[attr-defined]
        ), f"{algorithm} algorithm is not supported by python-jose library"

    @property
    def default_algorithm(self) -> str:
        return jwt.ALGORITHMS.HS256

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def encode(self, to_encode: Dict[str, Any], secret_key: str) -> str:
        return jwt.encode(to_encode, secret_key, algorithm=self._algorithm)

    def decode(self, token: str, secret_key: str, auto_error: bool) -> Optional[Dict[str, Any]]:
        try:
            payload: Dict[str, Any] = jwt.decode(
                token,
                secret_key,
                algorithms=[self._algorithm],
                options={"leeway": 10},
            )
            return payload
        except jwt.ExpiredSignatureError as e:  # type: ignore[attr-defined]
            if auto_error:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Token time expired: {e}")
            else:
                return None
        except jwt.JWTError as e:  # type: ignore[attr-defined]
            if auto_error:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Wrong token: {e}")
            else:
                return None
