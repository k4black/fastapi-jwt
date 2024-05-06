from typing import Any, Dict, Optional

try:
    import authlib.jose as authlib_jose
    import authlib.jose.errors as authlib_jose_errors
except ImportError:  # pragma: no cover
    authlib_jose = None

from .abstract_backend import AbstractJWTBackend, BackendException


class AuthlibJWTBackend(AbstractJWTBackend):
    def __init__(self, algorithm: Optional[str] = None) -> None:
        assert authlib_jose is not None, "To use AuthlibJWTBackend, you need to install authlib"

        self._algorithm = algorithm or self.default_algorithm
        # from https://github.com/lepture/authlib/blob/85f9ff/authlib/jose/__init__.py#L45
        assert (
            self._algorithm in authlib_jose.JsonWebSignature.ALGORITHMS_REGISTRY.keys()
        ), f"{self._algorithm} algorithm is not supported by authlib"
        self.jwt = authlib_jose.JsonWebToken(algorithms=[self._algorithm])

    @property
    def default_algorithm(self) -> str:
        return "HS256"

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def encode(self, to_encode: Dict[str, Any], secret_key: str) -> str:
        token = self.jwt.encode(header={"alg": self.algorithm}, payload=to_encode, key=secret_key)
        return token.decode()  # convert to string

    def decode(self, token: str, secret_key: str) -> Optional[Dict[str, Any]]:
        try:
            payload = self.jwt.decode(token, secret_key)
            payload.validate(leeway=10)
            return dict(payload)
        except authlib_jose_errors.ExpiredTokenError as e:
            raise BackendException(f"Token time expired: {e}")
        except (
            authlib_jose_errors.InvalidClaimError,
            authlib_jose_errors.InvalidTokenError,
            authlib_jose_errors.DecodeError,
        ) as e:
            raise BackendException(f"Invalid token: {e}")
