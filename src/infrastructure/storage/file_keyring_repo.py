from typing import override

from src.application.out.keyring_repo import KeyringRepo
from src.domain.key_ring import KeyRing
from src.infrastructure.storage.json_storage_adapter import (
    JSONPrivateKeyringAdapter,
    JSONPublicKeyringAdapter,
)


class FileKeyringRepo(KeyringRepo):
    """
    This class acts like a concrete implementation of keyring repo port. Also it's Facade for two concrete adapters that work with json implementation.
    """

    private_repo: JSONPrivateKeyringAdapter
    public_repo: JSONPublicKeyringAdapter

    def __init__(
        self,
        private_repo: JSONPrivateKeyringAdapter,
        public_repo: JSONPublicKeyringAdapter,
    ) -> None:
        super().__init__()
        self.private_repo = private_repo
        self.public_repo = public_repo

    @override
    def save_all(self, keyring: KeyRing) -> None:
        self.private_repo.save_data(keyring.get_private_ring())
        self.public_repo.save_data(keyring.get_public_ring())

    @override
    def save_private(self, keyring: KeyRing) -> None:
        self.private_repo.save_data(keyring.get_private_ring())

    @override
    def save_public(self, keyring: KeyRing) -> None:
        self.public_repo.save_data(keyring.get_public_ring())

    @override
    def load_all(self) -> KeyRing:
        public_ring = self.public_repo.load_data()
        private_ring = self.private_repo.load_data()

        return KeyRing(private_ring=private_ring, public_ring=public_ring)
