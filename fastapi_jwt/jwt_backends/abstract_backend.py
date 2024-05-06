from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BackendException(Exception):  # pragma: no cover
    pass


class AbstractJWTBackend(ABC):  # pragma: no cover
    @abstractmethod
    def __init__(self, algorithm: Optional[str] = None) -> None:
        raise NotImplementedError

    @property
    @abstractmethod
    def algorithm(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def encode(self, to_encode: Dict[str, Any], secret_key: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def decode(self, token: str, secret_key: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError
