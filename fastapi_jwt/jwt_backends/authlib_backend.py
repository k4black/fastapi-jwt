from typing import Any, Dict, Optional

from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED

try:
    import authlib.jose as authlib_jose
    import authlib.jose.errors as authlib_jose_errors
except ImportError:
    authlib_jose = None

from .abstract_backend import AbstractJWTBackend


class AuthlibJWTBackend(AbstractJWTBackend):
    def __init__(self, algorithm: Optional[str] = None) -> None:
        assert authlib_jose is not None, "To use AuthlibJWTBackend, you need to install authlib"

        self._algorithm = algorithm or self.default_algorithm
        # from https://github.com/lepture/authlib/blob/85f9ff/authlib/jose/__init__.py#L45
        valid_algorithms = authlib_jose.JsonWebSignature.ALGORITHMS_REGISTRY.keys()
        assert self._algorithm in valid_algorithms, f"{self._algorithm} algorithm is not supported by authlib"
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

    def decode(self, token: str, secret_key: str, auto_error: bool) -> Optional[Dict[str, Any]]:
        try:
            payload = self.jwt.decode(token, secret_key)
            payload.validate(leeway=10)
            return dict(payload)
        except authlib_jose_errors.ExpiredTokenError as e:
            if auto_error:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Token time expired: {e}")
            else:
                return None
        except (
            authlib_jose_errors.InvalidClaimError,
            authlib_jose_errors.InvalidTokenError,
            authlib_jose_errors.DecodeError,
        ) as e:
            if auto_error:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Wrong token: {e}")
            else:
                return None
