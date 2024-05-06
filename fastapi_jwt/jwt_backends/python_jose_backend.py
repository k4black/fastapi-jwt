import warnings
from typing import Any, Dict, Optional

try:
    import jose
    import jose.jwt
except ImportError:  # pragma: no cover
    jose = None  # type: ignore

from .abstract_backend import AbstractJWTBackend, BackendException


class PythonJoseJWTBackend(AbstractJWTBackend):
    def __init__(self, algorithm: Optional[str] = None) -> None:
        assert jose is not None, "To use PythonJoseJWTBackend, you need to install python-jose"
        warnings.warn("PythonJoseJWTBackend is deprecated as python-jose library is not maintained anymore.")

        self._algorithm = algorithm or self.default_algorithm
        assert (
            hasattr(jose.jwt.ALGORITHMS, self._algorithm) is True  # type: ignore[attr-defined]
        ), f"{algorithm} algorithm is not supported by python-jose library"

    @property
    def default_algorithm(self) -> str:
        return jose.jwt.ALGORITHMS.HS256  # type: ignore[attr-defined]

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def encode(self, to_encode: Dict[str, Any], secret_key: str) -> str:
        return jose.jwt.encode(to_encode, secret_key, algorithm=self._algorithm)

    def decode(self, token: str, secret_key: str) -> Optional[Dict[str, Any]]:
        try:
            payload: Dict[str, Any] = jose.jwt.decode(
                token,
                secret_key,
                algorithms=[self._algorithm],
                options={"leeway": 10},
            )
            return payload
        except jose.jwt.ExpiredSignatureError as e:  # type: ignore[attr-defined]
            raise BackendException(f"Token time expired: {e}")
        except jose.jwt.JWTError as e:  # type: ignore[attr-defined]
            raise BackendException(f"Invalid token: {e}")
