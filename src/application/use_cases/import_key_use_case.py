from typing import final

from src.application.out.crypto_service_port import CryptoServicePort
from src.application.out.keyring_repo import KeyringRepo
from src.domain.key_ring import KeyRing


@final
class ImportKeyUseCase:
    def __init__(
        self,
        keyring: KeyRing,
        keyring_repo: KeyringRepo,
        crypto_generator: CryptoServicePort,
    ) -> None:
        self._keyring = keyring
        self._keyring_repo = keyring_repo
        self._crypto_generator = crypto_generator

    def execute(
        self,
        filepath: str,
        my_email: str,
        name: str,
        foreign_email: str | None = None,
        foreign_owner_trust: float | None = None,
        passphrase: str | None = None,
    ):
        imported_structure = self._crypto_generator.import_key(
            filepath,
            my_email=my_email,
            name=name,
            foreign_email=foreign_email,
            foreign_owner_trust=foreign_owner_trust,
            passphrase=passphrase,
        )

        if isinstance(imported_structure, tuple):
            private_key, public_key = imported_structure
            self._keyring.add_key_to_both_rings(private_key, public_key)
            self._keyring_repo.save_all(self._keyring)
        else:
            self._keyring.add_key_to_public_ring(imported_structure)
            self._keyring_repo.save_public(keyring=self._keyring)

        return imported_structure
