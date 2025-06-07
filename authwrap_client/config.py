from enum import Flag, auto


class FeatureFlag(Flag):
    LOG_AUTHORIZATION_HEADERS = auto()  # For debugging purposes
    ENABLE_LEGACY_FEATURES = auto()     # Legacy == OAuth 2.0
