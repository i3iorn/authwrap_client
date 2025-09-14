import pytest

from authwrap_client.config import State, FeatureFlag


@pytest.fixture(autouse=True)
def reset_flags():
    # Ensure isolation across tests
    state = State()
    state.clear_flags()
    yield
    state.clear_flags()


def test_singleton_persists_flags_between_instances():
    s1 = State()
    s1.add_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    s2 = State()
    assert s2.has_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)


def test_remove_flag_removes_only_specified_flag():
    state = State()
    state.clear_flags()
    state.add_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    state.add_flag(FeatureFlag.ENABLE_LEGACY_FEATURES)

    # Remove one flag and ensure the other remains
    state.remove_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    assert not state.has_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    assert state.has_flag(FeatureFlag.ENABLE_LEGACY_FEATURES)


def test_remove_flag_noop_when_flag_not_set():
    state = State()
    state.clear_flags()
    state.add_flag(FeatureFlag.ENABLE_PASSWORD_FLOW)

    # Removing a different flag should have no effect
    state.remove_flag(FeatureFlag.ENABLE_IMPLICIT_FLOW)
    assert state.has_flag(FeatureFlag.ENABLE_PASSWORD_FLOW)
    assert not state.has_flag(FeatureFlag.ENABLE_IMPLICIT_FLOW)


def test_remove_flag_type_validation():
    state = State()

    class Dummy: ...

    with pytest.raises(ValueError):
        state.remove_flag(Dummy())


def test_clear_flags_resets_all():
    state = State()
    state.add_flag(FeatureFlag.ENABLE_PASSWORD_FLOW)
    state.add_flag(FeatureFlag.ENABLE_IMPLICIT_FLOW)
    state.clear_flags()
    assert state.flags == FeatureFlag.NONE
    for f in (
        FeatureFlag.ENABLE_PASSWORD_FLOW,
        FeatureFlag.ENABLE_IMPLICIT_FLOW,
        FeatureFlag.LOG_AUTHORIZATION_HEADERS,
        FeatureFlag.ENABLE_LEGACY_FEATURES,
    ):
        assert not state.has_flag(f)

