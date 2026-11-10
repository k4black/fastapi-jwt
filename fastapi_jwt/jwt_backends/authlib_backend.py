from typing import Any, Dict, Optional

try:
    from joserfc import errors, jwk, jws, jwt
except ImportError as e:  # pragma: no cover
    raise ImportError("No JWT backend found, please install 'fastapi-jwt[authlib]'") from e

from .abstract_backend import AbstractJWTBackend, BackendException


class AuthlibJWTBackend(AbstractJWTBackend):
    def __init__(self, algorithm: Optional[str] = None) -> None:
        self._algorithm = algorithm or self.default_algorithm
        if self._algorithm == "none" or self._algorithm not in jws.JWSRegistry.algorithms:
            raise ValueError(f"{self._algorithm} algorithm is not supported")

    @property
    def default_algorithm(self) -> str:
        return "HS256"

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def encode(self, to_encode: Dict[str, Any], secret_key: str) -> str:
        key = jwk.import_key(secret_key, "oct" if self.algorithm.startswith("HS") else None)
        return jwt.encode({"alg": self.algorithm}, to_encode.copy(), key, algorithms=[self.algorithm])

    def decode(self, token: str, secret_key: str) -> Optional[Dict[str, Any]]:
        try:
            key = jwk.import_key(secret_key, "oct" if self.algorithm.startswith("HS") else None)
            payload = jwt.decode(token, key, algorithms=[self.algorithm]).claims
            jwt.JWTClaimsRegistry(leeway=10, exp={"essential": True}).validate(payload)
            return payload
        except errors.ExpiredTokenError as e:
            raise BackendException(f"Token time expired: {e}") from e
        except errors.JoseError as e:
            raise BackendException(f"Invalid token: {e}") from e
