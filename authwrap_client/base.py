from typing import Protocol, Dict, Optional

class AuthStrategy(Protocol):
    """Defines a pluggable authorization strategy interface."""
    @property
    def auth_position(self) -> str:
        """Defines the position of the auth strategy in the request."""
        ...

    def modify_call(self, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        ...
