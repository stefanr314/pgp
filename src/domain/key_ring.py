from copy import deepcopy
from dataclasses import dataclass, field

from src.domain.exceptions import (
    KeyAlreadyExistsException,
    KeyNotFoundException,
    UnauthorizedMethodInvocation,
)
from src.domain.pgp_key import PGPPrivateKey, PGPPublicKey


@dataclass
class KeyRing:
    """
    This class serves as the Domain Model class for KeyRing.
    Currently in represent object stored in memory for working with the keyring.
    Not designed for multi-threaded use, since no thread-safety is provided.
    Only used in single local desktop app environment. Not scalable.
    """

    _private_ring: dict[str, PGPPrivateKey] = field(default_factory=dict)
    _public_ring: dict[str, PGPPublicKey] = field(default_factory=dict)

    def get_my_private_key(self, key_id: str) -> PGPPrivateKey | None:
        return self._private_ring[key_id]

    @property
    def private_ring(self) -> dict[str, PGPPrivateKey]:
        """
        Method for returning private ring.
        """
        return deepcopy(self._private_ring)

    @property
    def public_ring(self) -> dict[str, PGPPublicKey]:
        return deepcopy(self._public_ring)

    def add_key_to_private_ring(self, key: PGPPrivateKey):
        if key.key_id in self._private_ring:
            raise KeyAlreadyExistsException(key.key_id)

        self._private_ring[key.key_id] = key

    def add_key_to_public_ring(self, key: PGPPublicKey):
        if key.key_id in self._public_ring:
            raise KeyAlreadyExistsException(key.key_id)

        self._public_ring[key.key_id] = key

    def add_key_to_both_rings(
        self, private_key: PGPPrivateKey, public_ring: PGPPublicKey
    ):
        self.add_key_to_private_ring(private_key)
        self.add_key_to_public_ring(public_ring)

    def export_public_key(self, key_id: str) -> str:
        if key_id not in self._public_ring:
            raise KeyNotFoundException(key_id)

        public_pem = self._public_ring[key_id].public_key
        return public_pem

    def export_key_pair(self, key_id: str) -> str:
        """
        Method for exporting the key pair from pem format they are stored in.
        Just export encypted private key, since it contains the public key.
        This is solely for private use, so no additional public ring info is required.
        """
        if key_id not in self._private_ring:
            raise KeyNotFoundException(key_id)

        private_pem = self._private_ring[key_id].enc_private_key
        # public_pem = self._public_ring[key_id].public_key

        # return "\n".join([private_pem, public_pem])
        return private_pem

    def revoke_key(self, key_id: str) -> None:
        if key_id not in self._private_ring:
            raise KeyNotFoundException(key_id)

        self._private_ring[key_id] = self._private_ring[key_id].deactivate()
        self._public_ring[key_id].deactivate()

    def delete_foreign_public_key(self, key_id: str) -> None:
        if key_id not in self._public_ring:
            raise KeyNotFoundException(key_id)

        if key_id in self._private_ring:
            raise UnauthorizedMethodInvocation(key_id)

        del self._public_ring[key_id]
