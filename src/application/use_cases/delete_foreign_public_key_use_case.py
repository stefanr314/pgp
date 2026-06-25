from src.application.out.keyring_repo import KeyringRepo
from src.domain.key_ring import KeyRing


class DeleteForeignPublicKeyUseCase:
    _keyring: KeyRing
    _keyring_repo: KeyringRepo

    def __init__(self, keyring: KeyRing, keyring_repo: KeyringRepo):
        self._keyring = keyring
        self._keyring_repo = keyring_repo

    def execute(self, key_id: str):
        self._keyring.delete_foreign_public_key(key_id)

        self._keyring_repo.save_public(self._keyring)
