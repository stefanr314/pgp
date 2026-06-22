from dataclasses import dataclass, field

from src.domain.exceptions import KeyAlreadyExistsException
from src.domain.pgp_key import PGPPrivateKey, PGPPublicKey


@dataclass
class KeyRing:
    private_ring: dict[str, PGPPrivateKey] = field(default_factory=dict)
    public_ring: dict[str, PGPPublicKey] = field(default_factory=dict)

    def get_my_private_key(self, key_id: str) -> PGPPrivateKey | None:
        return self.private_ring[key_id]

    def get_private_ring(self) -> dict[str, PGPPrivateKey]:
        """
        Method for returning private ring.
        """
        return self.private_ring.copy()

    def get_public_ring(self) -> dict[str, PGPPublicKey]:
        return self.public_ring.copy()

    def add_key_to_private_ring(self, key: PGPPrivateKey):
        if key.key_id in self.private_ring:
            raise KeyAlreadyExistsException(key.key_id)

        self.private_ring[key.key_id] = key

    def add_key_to_public_ring(self, key: PGPPublicKey):
        if key.key_id in self.public_ring:
            raise KeyAlreadyExistsException(key.key_id)

        self.public_ring[key.key_id] = key

    def add_key_to_both_rings(
        self, private_key: PGPPrivateKey, public_ring: PGPPublicKey
    ):
        self.add_key_to_private_ring(private_key)
        self.add_key_to_public_ring(public_ring)
