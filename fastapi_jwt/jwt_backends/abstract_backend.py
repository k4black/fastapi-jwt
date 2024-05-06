from abc import ABCMeta, abstractmethod, abstractproperty
from typing import Any, Dict, Optional, Self


class AbstractJWTBackend(metaclass=ABCMeta):
    # simple "SingletonArgs" implementation to keep a JWTBackend per algorithm
    _instances: Dict[Any, "AbstractJWTBackend"] = {}

    def __new__(cls, algorithm: Optional[str]) -> "AbstractJWTBackend":
        instance_key = (cls, algorithm)
        if instance_key not in cls._instances:
            cls._instances[instance_key] = super(AbstractJWTBackend, cls).__new__(cls)
        return cls._instances[instance_key]

    @abstractmethod
    def __init__(self, algorithm: Optional[str]) -> None:
        raise NotImplementedError

    @property
    @abstractmethod
    def default_algorithm(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def algorithm(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def encode(self, to_encode: Dict[str, Any], secret_key: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def decode(self, token: str, secret_key: str, auto_error: bool) -> Optional[Dict[str, Any]]:
        raise NotImplementedError
