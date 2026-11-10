from abc import ABC
from datetime import UTC, datetime, timedelta
from math import isfinite
from typing import Any, Dict, Literal, Optional, Set, Type
from uuid import uuid4

from fastapi.exceptions import HTTPException
from fastapi.param_functions import Security
from fastapi.responses import Response
from fastapi.security import APIKeyCookie, HTTPBearer
from joserfc.errors import JoseError
from joserfc.jwt import JWTClaimsRegistry
from starlette.status import HTTP_401_UNAUTHORIZED

from .jwt_backends import AbstractJWTBackend, authlib_backend
from .jwt_backends.abstract_backend import BackendException

DEFAULT_JWT_BACKEND: Type[AbstractJWTBackend] = authlib_backend.AuthlibJWTBackend


def force_jwt_backend(cls: Type[AbstractJWTBackend]) -> None:
    global DEFAULT_JWT_BACKEND
    DEFAULT_JWT_BACKEND = cls


def utcnow() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "force_jwt_backend",
    "JwtAuthorizationCredentials",
    "JwtAccessBearer",
    "JwtAccessCookie",
    "JwtAccessBearerCookie",
    "JwtRefreshBearer",
    "JwtRefreshCookie",
    "JwtRefreshBearerCookie",
]


class JwtAuthorizationCredentials:
    def __init__(self, subject: Dict[str, Any], jti: Optional[str] = None, exp: Optional[float] = None):
        self.subject = subject
        self.jti = jti
        self.exp = exp

    def __getitem__(self, item: str) -> Any:
        return self.subject[item]


def _validate_payload(
    payload: Optional[Dict[str, Any]], token_type: str, claims_registry: Optional[JWTClaimsRegistry] = None
) -> Dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("subject"), dict):
        raise BackendException("Invalid token: 'subject' must be an object")
    if payload.get("type") != token_type:
        raise BackendException(f"Invalid token: 'type' is not '{token_type}'")
    exp = payload.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or (isinstance(exp, float) and not isfinite(exp)):
        raise BackendException("Invalid token: 'exp' must be a finite number")
    if payload.get("jti") is not None and not isinstance(payload["jti"], str):
        raise BackendException("Invalid token: 'jti' must be a string")
    if claims_registry is not None:
        try:
            claims_registry.validate(payload)
        except JoseError as e:
            raise BackendException(f"Invalid token: {e}") from e
    return payload


class JwtAuthBase(ABC):
    class JwtAccessCookie(APIKeyCookie):
        def __init__(self, *args: Any, **kwargs: Any):
            APIKeyCookie.__init__(self, *args, name="access_token_cookie", auto_error=False, **kwargs)

    class JwtRefreshCookie(APIKeyCookie):
        def __init__(self, *args: Any, **kwargs: Any):
            APIKeyCookie.__init__(self, *args, name="refresh_token_cookie", auto_error=False, **kwargs)

    class JwtAccessBearer(HTTPBearer):
        def __init__(self, *args: Any, **kwargs: Any):
            HTTPBearer.__init__(self, *args, auto_error=False, **kwargs)

    class JwtRefreshBearer(HTTPBearer):
        def __init__(self, *args: Any, **kwargs: Any):
            HTTPBearer.__init__(self, *args, auto_error=False, **kwargs)

    def __init__(
        self,
        secret_key: str,
        places: Optional[Set[str]] = None,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        self.jwt_backend = DEFAULT_JWT_BACKEND(algorithm)
        self.secret_key = secret_key
        self.audience = audience
        self.issuer = issuer
        claims_options: Dict[str, Any] = {}
        if audience is not None:
            claims_options["aud"] = {"essential": True, "value": audience}
        if issuer is not None:
            claims_options["iss"] = {"essential": True, "value": issuer}
        self._claims_registry = JWTClaimsRegistry(leeway=10, **claims_options) if claims_options else None

        self.places = places or {"header"}
        assert self.places.issubset({"header", "cookie"}), "only 'header' and/or 'cookie' places are supported"
        self.auto_error = auto_error
        self.access_expires_delta = access_expires_delta or timedelta(minutes=15)
        self.refresh_expires_delta = refresh_expires_delta or timedelta(days=31)

    @property
    def algorithm(self) -> str:
        return self.jwt_backend.algorithm

    @classmethod
    def from_other(
        cls,
        other: "JwtAuthBase",
        secret_key: Optional[str] = None,
        auto_error: Optional[bool] = None,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ) -> "JwtAuthBase":
        return cls(
            secret_key=secret_key or other.secret_key,
            auto_error=other.auto_error if auto_error is None else auto_error,
            algorithm=algorithm or other.algorithm,
            access_expires_delta=access_expires_delta or other.access_expires_delta,
            refresh_expires_delta=refresh_expires_delta or other.refresh_expires_delta,
            audience=other.audience if audience is None else audience,
            issuer=other.issuer if issuer is None else issuer,
        )

    def _generate_payload(
        self,
        subject: Dict[str, Any],
        expires_delta: timedelta,
        unique_identifier: str,
        token_type: str,
    ) -> Dict[str, Any]:
        now = utcnow()
        payload = {
            "subject": subject.copy(),  # main subject
            "type": token_type,  # 'access' or 'refresh' token
            "exp": now + expires_delta,  # expire time
            "iat": now,  # creation time
            "jti": unique_identifier,  # uuid
        }
        if self.audience is not None:
            payload["aud"] = self.audience
        if self.issuer is not None:
            payload["iss"] = self.issuer
        return payload

    async def _get_payload(
        self, bearer: Optional[HTTPBearer], cookie: Optional[APIKeyCookie], token_type: str
    ) -> Optional[Dict[str, Any]]:
        token: Optional[str] = None
        if bearer:
            token = str(bearer.credentials)  # type: ignore
        elif cookie:
            token = str(cookie)

        # Try to decode jwt token. auto_error on error
        try:
            if not token:
                raise BackendException("Credentials are not provided")
            payload = self.jwt_backend.decode(token, self.secret_key)
            return _validate_payload(payload, token_type, self._claims_registry)
        except BackendException as e:
            if self.auto_error:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=str(e))
            else:
                return None

    def create_access_token(
        self,
        subject: Dict[str, Any],
        expires_delta: Optional[timedelta] = None,
        unique_identifier: Optional[str] = None,
    ) -> str:
        expires_delta = expires_delta or self.access_expires_delta
        unique_identifier = unique_identifier or str(uuid4())
        to_encode = self._generate_payload(subject, expires_delta, unique_identifier, "access")
        return self.jwt_backend.encode(to_encode, self.secret_key)

    def create_refresh_token(
        self,
        subject: Dict[str, Any],
        expires_delta: Optional[timedelta] = None,
        unique_identifier: Optional[str] = None,
    ) -> str:
        expires_delta = expires_delta or self.refresh_expires_delta
        unique_identifier = unique_identifier or str(uuid4())
        to_encode = self._generate_payload(subject, expires_delta, unique_identifier, "refresh")
        return self.jwt_backend.encode(to_encode, self.secret_key)

    @staticmethod
    def set_access_cookie(
        response: Response,
        access_token: str,
        expires_delta: Optional[timedelta] = None,
        *,
        secure: bool = True,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        seconds_expires: Optional[int] = int(expires_delta.total_seconds()) if expires_delta else None
        response.set_cookie(
            key="access_token_cookie",
            value=access_token,
            httponly=httponly,
            secure=secure,
            samesite=samesite,
            max_age=seconds_expires,
        )

    @staticmethod
    def set_refresh_cookie(
        response: Response,
        refresh_token: str,
        expires_delta: Optional[timedelta] = None,
        *,
        secure: bool = True,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        seconds_expires: Optional[int] = int(expires_delta.total_seconds()) if expires_delta else None
        response.set_cookie(
            key="refresh_token_cookie",
            value=refresh_token,
            httponly=httponly,
            secure=secure,
            samesite=samesite,
            max_age=seconds_expires,
        )

    @staticmethod
    def unset_access_cookie(
        response: Response,
        *,
        secure: bool = True,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        response.delete_cookie("access_token_cookie", secure=secure, httponly=httponly, samesite=samesite)

    @staticmethod
    def unset_refresh_cookie(
        response: Response,
        *,
        secure: bool = True,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        response.delete_cookie("refresh_token_cookie", secure=secure, httponly=httponly, samesite=samesite)


class JwtAccess(JwtAuthBase):
    _bearer = JwtAuthBase.JwtAccessBearer()
    _cookie = JwtAuthBase.JwtAccessCookie()

    def __init__(
        self,
        secret_key: str,
        places: Optional[Set[str]] = None,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        super().__init__(
            secret_key,
            places=places,
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
            audience=audience,
            issuer=issuer,
        )

    async def _get_credentials(
        self,
        bearer: Optional[JwtAuthBase.JwtAccessBearer],
        cookie: Optional[JwtAuthBase.JwtAccessCookie],
    ) -> Optional[JwtAuthorizationCredentials]:
        payload = await self._get_payload(bearer, cookie, "access")

        if payload:
            return JwtAuthorizationCredentials(payload["subject"], payload.get("jti"), payload.get("exp"))
        return None


class JwtAccessBearer(JwtAccess):
    def __init__(
        self,
        secret_key: str,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"header"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
            audience=audience,
            issuer=issuer,
        )

    async def __call__(
        self, bearer: JwtAuthBase.JwtAccessBearer = Security(JwtAccess._bearer)
    ) -> Optional[JwtAuthorizationCredentials]:
        return await self._get_credentials(bearer=bearer, cookie=None)


class JwtAccessCookie(JwtAccess):
    def __init__(
        self,
        secret_key: str,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"cookie"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
            audience=audience,
            issuer=issuer,
        )

    async def __call__(
        self,
        cookie: JwtAuthBase.JwtAccessCookie = Security(JwtAccess._cookie),
    ) -> Optional[JwtAuthorizationCredentials]:
        return await self._get_credentials(bearer=None, cookie=cookie)


class JwtAccessBearerCookie(JwtAccess):
    def __init__(
        self,
        secret_key: str,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"header", "cookie"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
            audience=audience,
            issuer=issuer,
        )

    async def __call__(
        self,
        bearer: JwtAuthBase.JwtAccessBearer = Security(JwtAccess._bearer),
        cookie: JwtAuthBase.JwtAccessCookie = Security(JwtAccess._cookie),
    ) -> Optional[JwtAuthorizationCredentials]:
        return await self._get_credentials(bearer=bearer, cookie=cookie)


class JwtRefresh(JwtAuthBase):
    _bearer = JwtAuthBase.JwtRefreshBearer()
    _cookie = JwtAuthBase.JwtRefreshCookie()

    def __init__(
        self,
        secret_key: str,
        places: Optional[Set[str]] = None,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        super().__init__(
            secret_key,
            places=places,
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
            audience=audience,
            issuer=issuer,
        )

    async def _get_credentials(
        self,
        bearer: Optional[JwtAuthBase.JwtRefreshBearer],
        cookie: Optional[JwtAuthBase.JwtRefreshCookie],
    ) -> Optional[JwtAuthorizationCredentials]:
        payload = await self._get_payload(bearer, cookie, "refresh")

        if payload is None:
            return None

        return JwtAuthorizationCredentials(payload["subject"], payload.get("jti"), payload.get("exp"))


class JwtRefreshBearer(JwtRefresh):
    def __init__(
        self,
        secret_key: str,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"header"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
            audience=audience,
            issuer=issuer,
        )

    async def __call__(
        self, bearer: JwtAuthBase.JwtRefreshBearer = Security(JwtRefresh._bearer)
    ) -> Optional[JwtAuthorizationCredentials]:
        return await self._get_credentials(bearer=bearer, cookie=None)


class JwtRefreshCookie(JwtRefresh):
    def __init__(
        self,
        secret_key: str,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"cookie"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
            audience=audience,
            issuer=issuer,
        )

    async def __call__(
        self,
        cookie: JwtAuthBase.JwtRefreshCookie = Security(JwtRefresh._cookie),
    ) -> Optional[JwtAuthorizationCredentials]:
        return await self._get_credentials(bearer=None, cookie=cookie)


class JwtRefreshBearerCookie(JwtRefresh):
    def __init__(
        self,
        secret_key: str,
        auto_error: bool = True,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"header", "cookie"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
            audience=audience,
            issuer=issuer,
        )

    async def __call__(
        self,
        bearer: JwtAuthBase.JwtRefreshBearer = Security(JwtRefresh._bearer),
        cookie: JwtAuthBase.JwtRefreshCookie = Security(JwtRefresh._cookie),
    ) -> Optional[JwtAuthorizationCredentials]:
        return await self._get_credentials(bearer=bearer, cookie=cookie)
