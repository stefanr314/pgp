from abc import ABC, abstractmethod

from src.domain.key_ring import KeyRing


class KeyringRepo(ABC):
    """
    Abstract base class for providing storage mechanism. Acts like port.
    """

    @abstractmethod
    def save_all(self, keyring: KeyRing) -> None:
        pass

    @abstractmethod
    def load_all(self) -> KeyRing:
        pass

    @abstractmethod
    def save_private(self, keyring: KeyRing) -> None:
        pass

    @abstractmethod
    def save_public(self, keyring: KeyRing) -> None:
        pass
