try:
    from .authlib_backend import AuthlibJWTBackend
except ImportError:
    AuthlibJWTBackend = None

try:
    from .python_jose_backend import PythonJoseJWTBackend
except ImportError:
    PythonJoseJWTBackend = None
