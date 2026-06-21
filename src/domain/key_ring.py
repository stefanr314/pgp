from dataclasses import dataclass, field

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
        self.private_ring[key.key_id] = key
