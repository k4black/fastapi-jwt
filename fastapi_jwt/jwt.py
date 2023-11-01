from abc import ABC
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Set
from uuid import uuid4

from fastapi.exceptions import HTTPException
from fastapi.param_functions import Security
from fastapi.responses import Response
from fastapi.security import APIKeyCookie, HTTPBearer
from starlette.status import HTTP_401_UNAUTHORIZED

try:
    from jose import jwt
except ImportError:  # pragma: nocover
    jwt = None  # type: ignore[assignment]


def utcnow():
    try:
        from datetime import UTC
    except ImportError:  # pragma: nocover
        # UTC was added in python 3.12, as datetime.utcnow was
        # marked for deprecation.
        return datetime.utcnow()
    else:
        return datetime.now(UTC)


__all__ = [
    "JwtAuthorizationCredentials",
    "JwtAccessBearer",
    "JwtAccessCookie",
    "JwtAccessBearerCookie",
    "JwtRefreshBearer",
    "JwtRefreshCookie",
    "JwtRefreshBearerCookie",
]


class JwtAuthorizationCredentials:
    def __init__(self, subject: Dict[str, Any], jti: Optional[str] = None):
        self.subject = subject
        self.jti = jti

    def __getitem__(self, item: str) -> Any:
        return self.subject[item]


class JwtAuthBase(ABC):
    class JwtAccessCookie(APIKeyCookie):
        def __init__(self, *args: Any, **kwargs: Any):
            APIKeyCookie.__init__(
                self, *args, name="access_token_cookie", auto_error=False, **kwargs
            )

    class JwtRefreshCookie(APIKeyCookie):
        def __init__(self, *args: Any, **kwargs: Any):
            APIKeyCookie.__init__(
                self, *args, name="refresh_token_cookie", auto_error=False, **kwargs
            )

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
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        assert jwt is not None, "python-jose must be installed to use JwtAuth"
        if places:
            assert places.issubset(
                {"header", "cookie"}
            ), "only 'header'/'cookie' are supported"
        algorithm = algorithm.upper()
        assert (
            hasattr(jwt.ALGORITHMS, algorithm) is True  # type: ignore[attr-defined]
        ), f"{algorithm} algorithm is not supported by python-jose library"

        self.secret_key = secret_key

        self.places = places or {"header"}
        self.auto_error = auto_error
        self.algorithm = algorithm
        self.access_expires_delta = access_expires_delta or timedelta(minutes=15)
        self.refresh_expires_delta = refresh_expires_delta or timedelta(days=31)

    @classmethod
    def from_other(
        cls,
        other: 'JwtAuthBase',
        secret_key: Optional[str] = None,
        auto_error: Optional[bool] = None,
        algorithm: Optional[str] = None,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ) -> 'JwtAuthBase':
        return cls(
            secret_key=secret_key or other.secret_key,
            auto_error=auto_error or other.auto_error,
            algorithm=algorithm or other.algorithm,
            access_expires_delta=access_expires_delta or other.access_expires_delta,
            refresh_expires_delta=refresh_expires_delta or other.refresh_expires_delta,
        )

    def _decode(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload: Dict[str, Any] = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"leeway": 10},
            )
            return payload
        except jwt.ExpiredSignatureError as e:  # type: ignore[attr-defined]
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail=f"Token time expired: {e}"
                )
            else:
                return None
        except jwt.JWTError as e:  # type: ignore[attr-defined]
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail=f"Wrong token: {e}"
                )
            else:
                return None

    def _generate_payload(
        self,
        subject: Dict[str, Any],
        expires_delta: timedelta,
        unique_identifier: str,
        token_type: str,
    ) -> Dict[str, Any]:
        now = utcnow()

        return {
            "subject": subject.copy(),  # main subject
            "type": token_type,  # 'access' or 'refresh' token
            "exp": now + expires_delta,  # expire time
            "iat": now,  # creation time
            "jti": unique_identifier,  # uuid
        }

    async def _get_payload(
        self, bearer: Optional[HTTPBearer], cookie: Optional[APIKeyCookie]
    ) -> Optional[Dict[str, Any]]:
        token: Optional[str] = None
        if bearer:
            token = str(bearer.credentials)  # type: ignore
        elif cookie:
            token = str(cookie)

        # Check token exist
        if not token:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail="Credentials are not provided"
                )
            else:
                return None

        # Try to decode jwt token. auto_error on error
        payload = self._decode(token)
        return payload

    def create_access_token(
        self,
        subject: Dict[str, Any],
        expires_delta: Optional[timedelta] = None,
        unique_identifier: Optional[str] = None,
    ) -> str:
        expires_delta = expires_delta or self.access_expires_delta
        unique_identifier = unique_identifier or str(uuid4())
        to_encode = self._generate_payload(
            subject, expires_delta, unique_identifier, "access"
        )

        jwt_encoded: str = jwt.encode(
            to_encode, self.secret_key, algorithm=self.algorithm
        )
        return jwt_encoded

    def create_refresh_token(
        self,
        subject: Dict[str, Any],
        expires_delta: Optional[timedelta] = None,
        unique_identifier: Optional[str] = None,
    ) -> str:
        expires_delta = expires_delta or self.refresh_expires_delta
        unique_identifier = unique_identifier or str(uuid4())
        to_encode = self._generate_payload(
            subject, expires_delta, unique_identifier, "refresh"
        )

        jwt_encoded: str = jwt.encode(
            to_encode, self.secret_key, algorithm=self.algorithm
        )
        return jwt_encoded

    @staticmethod
    def set_access_cookie(
        response: Response, access_token: str, expires_delta: Optional[timedelta] = None
    ) -> None:
        seconds_expires: Optional[int] = (
            int(expires_delta.total_seconds()) if expires_delta else None
        )
        response.set_cookie(
            key="access_token_cookie",
            value=access_token,
            httponly=False,
            max_age=seconds_expires,
        )

    @staticmethod
    def set_refresh_cookie(
        response: Response,
        refresh_token: str,
        expires_delta: Optional[timedelta] = None,
    ) -> None:
        seconds_expires: Optional[int] = (
            int(expires_delta.total_seconds()) if expires_delta else None
        )
        response.set_cookie(
            key="refresh_token_cookie",
            value=refresh_token,
            httponly=True,
            max_age=seconds_expires,
        )

    @staticmethod
    def unset_access_cookie(response: Response) -> None:
        response.set_cookie(
            key="access_token_cookie", value="", httponly=False, max_age=-1
        )

    @staticmethod
    def unset_refresh_cookie(response: Response) -> None:
        response.set_cookie(
            key="refresh_token_cookie", value="", httponly=True, max_age=-1
        )


class JwtAccess(JwtAuthBase):
    _bearer = JwtAuthBase.JwtAccessBearer()
    _cookie = JwtAuthBase.JwtAccessCookie()

    def __init__(
        self,
        secret_key: str,
        places: Optional[Set[str]] = None,
        auto_error: bool = True,
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        super().__init__(
            secret_key,
            places=places,
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
        )

    async def _get_credentials(
        self,
        bearer: Optional[JwtAuthBase.JwtAccessBearer],
        cookie: Optional[JwtAuthBase.JwtAccessCookie],
    ) -> Optional[JwtAuthorizationCredentials]:
        payload = await self._get_payload(bearer, cookie)

        if payload:
            return JwtAuthorizationCredentials(
                payload["subject"], payload.get("jti", None)
            )
        return None


class JwtAccessBearer(JwtAccess):
    def __init__(
        self,
        secret_key: str,
        auto_error: bool = True,
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"header"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
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
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"cookie"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
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
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"header", "cookie"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
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
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        super().__init__(
            secret_key,
            places=places,
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
        )

    async def _get_credentials(
        self,
        bearer: Optional[JwtAuthBase.JwtRefreshBearer],
        cookie: Optional[JwtAuthBase.JwtRefreshCookie],
    ) -> Optional[JwtAuthorizationCredentials]:
        payload = await self._get_payload(bearer, cookie)

        if payload is None:
            return None

        if "type" not in payload or payload["type"] != "refresh":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Wrong token: 'type' is not 'refresh'",
                )
            else:
                return None

        return JwtAuthorizationCredentials(
            payload["subject"], payload.get("jti", None)
        )


class JwtRefreshBearer(JwtRefresh):
    def __init__(
        self,
        secret_key: str,
        auto_error: bool = True,
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"header"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
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
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"cookie"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
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
        algorithm: str = jwt.ALGORITHMS.HS256,  # type: ignore[attr-defined]
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
    ):
        super().__init__(
            secret_key=secret_key,
            places={"header", "cookie"},
            auto_error=auto_error,
            algorithm=algorithm,
            access_expires_delta=access_expires_delta,
            refresh_expires_delta=refresh_expires_delta,
        )

    async def __call__(
        self,
        bearer: JwtAuthBase.JwtRefreshBearer = Security(JwtRefresh._bearer),
        cookie: JwtAuthBase.JwtRefreshCookie = Security(JwtRefresh._cookie),
    ) -> Optional[JwtAuthorizationCredentials]:
        return await self._get_credentials(bearer=bearer, cookie=cookie)
