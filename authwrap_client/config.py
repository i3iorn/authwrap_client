from enum import Flag, auto


class FeatureFlag(Flag):
    NONE = auto()
    LOG_AUTHORIZATION_HEADERS = auto()  # For debugging purposes
    ENABLE_LEGACY_FEATURES = auto()     # Legacy == OAuth 2.0
    ENABLE_PASSWORD_FLOW = auto()       # Enable password flow for OAuth 2.0
    ENABLE_IMPLICIT_FLOW = auto()       # Enable implicit flow for OAuth 2.0


class State:
    _instance = None
    _instantiated = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(State, cls).__new__(cls)
            cls._instantiated = True
        return cls._instance

    def __init__(self):
        if self._instantiated:
            return

        self.flags = FeatureFlag.NONE

    def set_flags(self, flags: FeatureFlag):
        """
        Set the feature flags for the application.

        Args:
            flags (FeatureFlag): The feature flags to set.
        """
        if not isinstance(flags, FeatureFlag):
            raise ValueError("flags must be an instance of FeatureFlag")
        self.flags = flags

    def has_flag(self, flag: FeatureFlag) -> bool:
        """
        Check if a specific feature flag is set.
        """
        if not isinstance(flag, FeatureFlag):
            raise ValueError("flag must be an instance of FeatureFlag")
        return flag in self.flags

    def clear_flags(self):
        """
        Clear all feature flags.
        """
        self.flags = FeatureFlag.NONE

    def add_flag(self, flag: FeatureFlag):
        """
        Add a feature flag to the current flags.

        Args:
            flag (FeatureFlag): The feature flag to add.
        """
        if not isinstance(flag, FeatureFlag):
            raise ValueError("flag must be an instance of FeatureFlag")
        self.flags |= flag

    def is_feature_enabled(self, feature: FeatureFlag) -> bool:
        """
        Check if a specific feature is enabled based on the current flags.

        Args:
            feature (FeatureFlag): The feature to check.

        Returns:
            bool: True if the feature is enabled, False otherwise.
        """
        return self.has_flag(feature)

    def remove_flag(self, flag: FeatureFlag):
        """
        Remove a feature flag from the current flags.

        Args:
            flag (FeatureFlag): The feature flag to remove.
        """
        if not isinstance(flag, FeatureFlag):
            raise ValueError("flag must be an instance of FeatureFlag")
        self.flags &= ~flag
