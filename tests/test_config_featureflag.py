import pytest
from authwrap_client.config import FeatureFlag, State

class DummyFlag:
    pass

def test_feature_flag_combinations():
    assert FeatureFlag.LOG_AUTHORIZATION_HEADERS != FeatureFlag.ENABLE_LEGACY_FEATURES
    combined = FeatureFlag.LOG_AUTHORIZATION_HEADERS | FeatureFlag.ENABLE_LEGACY_FEATURES
    assert FeatureFlag.LOG_AUTHORIZATION_HEADERS in combined
    assert FeatureFlag.ENABLE_LEGACY_FEATURES in combined
    assert FeatureFlag.NONE not in combined

def test_state_singleton():
    s1 = State()
    s2 = State()
    assert s1 is s2

def test_set_flags_and_has_flag():
    state = State()
    state.set_flags(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    assert state.has_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    assert not state.has_flag(FeatureFlag.ENABLE_LEGACY_FEATURES)

    with pytest.raises(ValueError):
        state.set_flags(DummyFlag())
    with pytest.raises(ValueError):
        state.has_flag(DummyFlag())

def test_clear_flags():
    state = State()
    state.set_flags(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    state.clear_flags()
    assert not state.has_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    assert state.flags == FeatureFlag.NONE

def test_add_flag():
    state = State()
    state.clear_flags()
    state.add_flag(FeatureFlag.ENABLE_LEGACY_FEATURES)
    assert state.has_flag(FeatureFlag.ENABLE_LEGACY_FEATURES)
    state.add_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    assert state.has_flag(FeatureFlag.LOG_AUTHORIZATION_HEADERS)
    with pytest.raises(ValueError):
        state.add_flag(DummyFlag())

def test_is_feature_enabled():
    state = State()
    state.set_flags(FeatureFlag.ENABLE_PASSWORD_FLOW)
    assert state.is_feature_enabled(FeatureFlag.ENABLE_PASSWORD_FLOW)
    assert not state.is_feature_enabled(FeatureFlag.ENABLE_IMPLICIT_FLOW)
    with pytest.raises(ValueError):
        state.is_feature_enabled(DummyFlag())

