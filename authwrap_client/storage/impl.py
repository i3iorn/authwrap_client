from typing import Dict, Optional

from authwrap_client.storage.protocol import StorageProtocol


class InMemoryStorage(StorageProtocol):
    """A simple in-memory storage for OAuth tokens."""

    def __init__(self):
        self._storage: Dict[str, str] = {}

    def set(self, key: str, value: str) -> None:
        """Store a value under the given key."""
        self._storage[key] = value

    def get(self, key: str) -> Optional[str]:
        """Retrieve a value by its key, or None if not found."""
        return self._storage.get(key)

    def delete(self, key: str) -> None:
        """Delete a value by its key."""
        if key in self._storage:
            del self._storage[key]

    def clear(self) -> None:
        """Clear all stored values."""
        self._storage.clear()