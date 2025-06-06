class AuthWrapException(Exception):
    """Base exception for AuthWrap errors."""
    pass


class InjectionError(AuthWrapException):
    """Raised when there is an error injecting auth data."""
    pass


class AuthStrategyError(AuthWrapException):
    """Raised when there is an error with the authentication strategy."""
    pass


class AuthWrapConfigurationError(AuthWrapException):
    """Raised when there is a configuration error in AuthWrap."""
    pass