try:
    from .authlib_backend import AuthlibJWTBackend
except ImportError:
    AuthlibJWTBackend = None  # type: ignore

try:
    from .python_jose_backend import PythonJoseJWTBackend
except ImportError:
    PythonJoseJWTBackend = None  # type: ignore

from .abstract_backend import AbstractJWTBackend  # noqa: F401
