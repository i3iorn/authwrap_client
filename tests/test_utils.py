import inspect
import pytest

from authwrap_client.utils import insecure
from authwrap_client.config import State, FeatureFlag


@pytest.fixture(autouse=True)
def reset_flags():
    # Ensure feature flags are reset before and after each test for isolation
    state = State()
    state.clear_flags()
    yield
    state.clear_flags()


def test_insecure_function_blocks_without_flag_and_runs_with_flag():
    flag = FeatureFlag.ENABLE_LEGACY_FEATURES

    @insecure(flag, "do not call")
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    # Without flag -> blocked
    with pytest.raises(RuntimeError, match=r"^Insecure function called: do not call$"):
        add(1, 2)

    # Metadata preserved
    assert add.__name__ == "add"
    assert add.__doc__ == "Add two integers."
    assert hasattr(add, "__wrapped__")
    # Signature preserved via wraps
    assert str(inspect.signature(add)) == "(a: int, b: int) -> int"

    # With flag -> allowed
    State().add_flag(flag)
    assert add(1, 2) == 3


def test_insecure_on_staticmethod_both_orders():
    flag = FeatureFlag.ENABLE_LEGACY_FEATURES

    class A:
        @insecure(flag, "blocked")
        @staticmethod
        def times2(x):
            return x * 2

    class B:
        @staticmethod
        @insecure(flag, "blocked")
        def times2(x):
            return x * 2

    # Without flag -> blocked
    with pytest.raises(RuntimeError, match=r"^Insecure function called: blocked$"):
        A.times2(3)
    with pytest.raises(RuntimeError, match=r"^Insecure function called: blocked$"):
        B.times2(4)

    # With flag -> allowed
    State().add_flag(flag)
    assert A.times2(3) == 6
    assert B.times2(4) == 8


def test_insecure_on_classmethod_both_orders():
    flag = FeatureFlag.ENABLE_LEGACY_FEATURES

    class C:
        @insecure(flag, "blocked")
        @classmethod
        def ident(cls, x):
            return f"{cls.__name__}:{x}"

    class D:
        @classmethod
        @insecure(flag, "blocked")
        def ident(cls, x):
            return f"{cls.__name__}:{x}"

    # Without flag -> blocked
    with pytest.raises(RuntimeError, match=r"^Insecure function called: blocked$"):
        C.ident(10)
    with pytest.raises(RuntimeError, match=r"^Insecure function called: blocked$"):
        D.ident(20)

    # With flag -> allowed (call via class and instance)
    State().add_flag(flag)
    assert C.ident(10) == "C:10"
    assert D().ident(20) == "D:20"


def test_insecure_on_class_blocks_init_and_preserves_metadata():
    flag = FeatureFlag.ENABLE_LEGACY_FEATURES

    @insecure(flag, "nope")
    class Dangerous:
        """A class that should be gated by a feature flag."""
        def __init__(self, value):
            self.value = value
        def get(self):
            return self.value

    # Without flag -> instantiation blocked
    with pytest.raises(RuntimeError, match=r"^Insecure class instantiated: nope$"):
        Dangerous(1)

    # Metadata preserved on wrapped class
    assert Dangerous.__name__ == "Dangerous"
    assert Dangerous.__doc__ == "A class that should be gated by a feature flag."

    # With flag -> instantiation allowed
    State().add_flag(flag)
    d = Dangerous(2)
    assert d.get() == 2
    # Instance is of the decorated class name
    assert isinstance(d, Dangerous)


def test_insecure_class_decorator_maintains_subclassing_relation_and_doc():
    flag = FeatureFlag.ENABLE_LEGACY_FEATURES

    class Original:
        """Original class doc."""
        def __init__(self, v):
            self.v = v

    Decorated = insecure(flag, "nope")(Original)

    # Wrapped is a subclass of the original and preserves metadata
    assert issubclass(Decorated, Original)
    assert Decorated.__name__ == Original.__name__
    assert Decorated.__doc__ == Original.__doc__

    with pytest.raises(RuntimeError, match=r"^Insecure class instantiated: nope$"):
        Decorated(5)
    State().add_flag(flag)
    obj = Decorated(6)
    assert isinstance(obj, Original)
    assert obj.v == 6


def test_insecure_decorator_rejects_unsupported_targets():
    flag = FeatureFlag.ENABLE_LEGACY_FEATURES
    dec = insecure(flag, "x")
    with pytest.raises(TypeError):
        dec(42)

