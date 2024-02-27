from abc import ABCMeta, abstractmethod, abstractproperty
from typing import Any, Dict, Optional, Self



class AbstractJWTBackend(metaclass=ABCMeta):

    # simple "SingletonArgs" implementation to keep a JWTBackend per algorithm
    _instances = {}

    def __new__(cls, algorithm) -> Self:
        instance_key = (cls, algorithm)
        if instance_key not in cls._instances:
            cls._instances[instance_key] = super(AbstractJWTBackend, cls).__new__(cls)
        return cls._instances[instance_key]

    @abstractmethod
    def __init__(self, algorithm) -> None:
        pass

    @abstractproperty
    def default_algorithm(self) -> str:
        pass

    @abstractmethod
    def encode(self, to_encode, secret_key) -> str:
        pass

    @abstractmethod
    def decode(self, token, secret_key, auto_error) -> Optional[Dict[str, Any]]:
        pass
