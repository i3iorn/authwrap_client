from typing import Dict, Optional

from authwrap_client.base import RequestProtocol
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


class SqliteStorage(StorageProtocol):
    """A simple SQLite storage for OAuth tokens."""

    def __init__(self, db_path: str):
        import sqlite3
        self._conn = sqlite3.connect(db_path)
        self._create_table()

    def _create_table(self):
        cursor = self._conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        self._conn.commit()

    def set(self, key: str, value: str) -> None:
        cursor = self._conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO tokens (key, value) VALUES (?, ?)', (key, value))
        self._conn.commit()

    def get(self, key: str) -> Optional[str]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT value FROM tokens WHERE key = ?', (key,))
        row = cursor.fetchone()
        return row[0] if row else None

    def delete(self, key: str) -> None:
        cursor = self._conn.cursor()
        cursor.execute('DELETE FROM tokens WHERE key = ?', (key,))
        self._conn.commit()

    def clear(self) -> None:
        cursor = self._conn.cursor()
        cursor.execute('DELETE FROM tokens')
        self._conn.commit()
