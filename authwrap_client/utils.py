import logging
import warnings
import inspect

from functools import wraps
from typing import Callable

from authwrap_client.config import State, FeatureFlag


class InsecureWarning(Warning):
    """
    Custom warning for insecure functions and classes.

    This warning is raised when a function or class is marked as insecure
    using the `insecure` decorator. It indicates that the function or class
    should not be used in production environments.
    """
    pass


def insecure(flag: FeatureFlag, msg: str) -> Callable:
    """
    Decorator for marking functions and classes as insecure.

    This decorator is used to indicate that a function or class is insecure
    and should not be used in production environments. It raises a RuntimeError
    with the provided message when the function or class is called, unless the
    `FeatureFlag` is set.
    Handles static methods, class methods, and preserves all metadata.
    """
    def decorator(decorated_object):
        if inspect.isclass(decorated_object):
            return _insecure_class(decorated_object, flag, msg)
        elif inspect.isfunction(decorated_object):
            return _insecure_function(decorated_object, flag, msg)
        elif isinstance(decorated_object, staticmethod):
            func = decorated_object.__func__
            return staticmethod(_insecure_function(func, flag, msg))
        elif isinstance(decorated_object, classmethod):
            func = decorated_object.__func__
            return classmethod(_insecure_function(func, flag, msg))
        else:
            raise TypeError("The `insecure` decorator can only be applied to functions, methods, or classes.")
    return decorator


def _insecure_function(func, flag: FeatureFlag, msg: str) -> Callable:
    """
    Decorator for marking functions as insecure.

    This function wraps the original function and raises a RuntimeError with the
    provided message if the `FeatureFlag` is not set.
    Handles static and class methods.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not State().has_flag(flag):
            raise RuntimeError(f"Insecure function called: {msg}")
        return func(*args, **kwargs)
    return wrapper


def _insecure_class(cls, flag: FeatureFlag, msg: str) -> Callable:
    """
    Decorator for marking classes as insecure.

    This function wraps the original class and raises a RuntimeError with the
    provided message if the `FeatureFlag` is not set.
    Preserves all class metadata.
    """
    import functools
    class WrappedClass(cls):
        def __init__(self, *args, **kwargs):
            if not State().has_flag(flag):
                raise RuntimeError(f"Insecure class instantiated: {msg}")
            super().__init__(*args, **kwargs)
    functools.update_wrapper(WrappedClass, cls, updated=())
    return WrappedClass