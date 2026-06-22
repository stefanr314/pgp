from typing import Literal

from src.application.out.crypto_service_port import CryptoServicePort
from src.application.out.keyring_repo import KeyringRepo
from src.domain.key_ring import KeyRing
from src.domain.pgp_key import PGPPrivateKey, PGPPublicKey


class GenerateKeyPairUseCase:
    keyring: KeyRing
    keyring_repo: KeyringRepo
    crypto_generator: CryptoServicePort

    def __init__(
        self,
        keyring: KeyRing,
        keyring_repo: KeyringRepo,
        crypto_generator: CryptoServicePort,
    ):
        self.keyring = keyring
        self.keyring_repo = keyring_repo
        self.crypto_generator = crypto_generator

    def execute(
        self, name: str, email: str, keysize: Literal[1024, 2048], passphrase: str
    ) -> tuple[PGPPrivateKey, PGPPublicKey]:
        # call the adequate port method for generating the key generating key pairs
        pgp_private_key, pgp_public_key = self.crypto_generator.generate_key_pair(
            name=name, email=email, key_size=keysize, passphrase=passphrase
        )

        # save them to the key repo, may rise an error for presenter
        self.keyring.add_key_to_both_rings(pgp_private_key, pgp_public_key)
        self.keyring_repo.save_all(keyring=self.keyring)

        # return adequate model info (domain model perhaps) for presenter
        return pgp_private_key, pgp_public_key
