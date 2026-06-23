from abc import ABC, abstractmethod
from typing import Literal

from src.domain.pgp_key import PGPPrivateKey, PGPPublicKey


class CryptoServicePort(ABC):
    @abstractmethod
    def generate_key_pair(
        self, name: str, email: str, key_size: Literal[1024, 2048], passphrase: str
    ) -> tuple[PGPPrivateKey, PGPPublicKey]:
        pass

    @abstractmethod
    def import_key(
        self,
        filepath: str,
        my_email: str,
        name: str,
        foreign_email: str | None = None,
        foreign_owner_trust: float | None = None,
        passphrase: str | None = None,
    ) -> tuple[PGPPrivateKey, PGPPublicKey] | PGPPublicKey:
        pass

    # @abstractmethod
    # def import_public_key(
    #     self,
    #     filepath: str,
    #     my_email: str,
    #     foreign_email: str | None = None,
    #     foreign_owner_trust: float | None = None,
    # ) -> PGPPublicKey:
    #     pass
    #
    # @abstractmethod
    # def import_key_pair(
    #     self, filepath_private_key: str, filepath_public_key: str, my_email: str
    # ) -> tuple[PGPPrivateKey, PGPPublicKey]:
    #     pass
