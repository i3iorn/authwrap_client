from typing import Protocol


class StorageProtocol(Protocol):
    """Defines a pluggable storage interface for auth data."""

    def get(self, key: str) -> str:
        """Retrieve a value from storage by key."""
        ...

    def set(self, key: str, value: str) -> None:
        """Store a value in storage with the specified key."""
        ...

    def delete(self, key: str) -> None:
        """Delete a value from storage by key."""
        ...

    def clear(self) -> None:
        """Clear all values from storage."""
        ...

    def keys(self) -> list[str]:
        """Return a list of all keys in storage."""
        ...
