from typing import override, Literal
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from src.application.out.crypto_service_port import CryptoServicePort
from src.domain.exceptions import (
    InvalidFileFormatException,
    InvalidKeyFormatException,
    InvalidPasswordRequirementException,
    PasswordMismatchException,
)
from src.domain.pgp_key import PGPPrivateKey, PGPPublicKey


class RSAGeneratorAdapter(CryptoServicePort):
    @override
    def generate_key_pair(
        self, name: str, email: str, key_size: Literal[1024, 2048], passphrase: str
    ) -> tuple[PGPPrivateKey, PGPPublicKey]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        pgp_private_domain = self._rsa_to_private_pgp_key(
            private_key, my_email=email, name=name, passphrase=passphrase
        )

        pgp_public_domain = self._rsa_to_public_pgp_key(
            private_key.public_key(), my_email=email
        )

        return pgp_private_domain, pgp_public_domain

    @override
    def import_key(
        self,
        filepath: str,
        my_email: str,
        name: str,
        foreign_email: str | None = None,
        foreign_owner_trust: float | None = None,
        passphrase: str | None = None,
    ) -> tuple[PGPPrivateKey, PGPPublicKey] | PGPPublicKey:
        try:
            with open(file=filepath, mode="rb") as key_file:
                pem_data = key_file.read()
        except FileNotFoundError as e:
            raise InvalidFileFormatException(filepath=filepath) from e
        else:
            if b"PRIVATE KEY" in pem_data:
                # handle private load
                pgp_private_domain, pgp_public_domain = self._load_private_key(
                    pem_data, filepath, my_email, name, passphrase
                )
                return pgp_private_domain, pgp_public_domain
            elif b"PUBLIC KEY" in pem_data:
                # handle public key load
                pgp_public = self._load_public_key(
                    pem_data=pem_data,
                    filepath=filepath,
                    my_email=my_email,
                    foreign_email=foreign_email,
                    foreign_owner_trust=foreign_owner_trust,
                )
                return pgp_public
            else:
                raise InvalidFileFormatException(filepath)

    def _load_private_key(
        self,
        pem_data: bytes,
        filepath: str,
        my_email: str,
        name: str,
        passphrase: str | None = None,
    ):
        try:
            pgp_raw = serialization.load_pem_private_key(
                pem_data,
                password=bytes(passphrase, "utf-8") if passphrase else None,
            )
        except ValueError as e:
            if passphrase is not None:
                raise PasswordMismatchException(filepath=filepath) from e
            raise InvalidKeyFormatException(keypath=filepath) from e
        except TypeError as exc:
            message = "Password required but not provided. Please provide a password"
            if passphrase is not None:
                message = "Password provided but not required. Please do not provide a password"
            raise InvalidPasswordRequirementException(filepath, message) from exc
        else:
            # create domain object an return it
            if isinstance(pgp_raw, RSAPrivateKey):
                pgp_private_domain = self._rsa_to_private_pgp_key(
                    pgp_raw, my_email, name, passphrase
                )
                pgp_public_domain = self._rsa_to_public_pgp_key(
                    pgp_raw.public_key(), my_email
                )

                return pgp_private_domain, pgp_public_domain
            else:
                # this is RSA only adapter
                raise InvalidKeyFormatException(keypath=filepath)

    def _load_public_key(
        self,
        pem_data: bytes,
        filepath: str,
        my_email: str,
        foreign_email: str | None = None,
        foreign_owner_trust: float | None = None,
    ) -> PGPPublicKey:
        try:
            public_key = serialization.load_pem_public_key(pem_data)

        except (ValueError, UnsupportedAlgorithm) as e:
            raise InvalidKeyFormatException(filepath) from e
        else:
            if isinstance(public_key, rsa.RSAPublicKey):
                pgp_public_domain = self._rsa_to_public_pgp_key(
                    public_key, my_email, foreign_email, foreign_owner_trust
                )
                return pgp_public_domain
            else:
                # this is RSA only adapter
                raise InvalidKeyFormatException(filepath)

    def _rsa_to_public_pgp_key(
        self,
        rsa_public_key: RSAPublicKey,
        my_email: str,
        foreign_email: str | None = None,
        foreign_owner_trust: float | None = None,
    ) -> PGPPublicKey:
        public_number: int = rsa_public_key.public_numbers().n

        key_id_hex: str = self._extract_key_id_hex(public_number)

        key_size = rsa_public_key.key_size

        owner_trust = 1.0
        if foreign_owner_trust is not None:
            owner_trust = foreign_owner_trust

        user_id = my_email
        if foreign_email is not None:
            user_id = foreign_email

        pgp_raw = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pgp_public: PGPPublicKey = PGPPublicKey(
            _user_id=user_id,
            _key_id=key_id_hex,
            _public_key=pgp_raw.decode("utf-8"),
            _owner_trust=owner_trust,
            _key_legitimacy=1.0,
            _signatures=list(),
            _signature_trust=0.0,
            _key_size=key_size,
        )

        return pgp_public

    def _rsa_to_private_pgp_key(
        self,
        rsa_private_key: RSAPrivateKey,
        my_email: str,
        name: str,
        passphrase: str | None,
    ):

        public_key = rsa_private_key.public_key()

        # 2. key_id mod 2^64
        public_number: int = public_key.public_numbers().n

        key_id_hex: str = self._extract_key_id_hex(public_number)

        key_size: int = rsa_private_key.key_size
        # 3. encode public key to pem format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # 4. generate hash from passphrase, this is not required since relying on internal serialization implementation
        # digest = Hash(SHA1())
        # digest.update(b'passphrase')
        # digest_bytes: bytes = digest.finalize()

        # 5. encrypt private key with symmetric enc, rely on internal implementation aes-256 with passphrase provided
        private_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                bytes(passphrase, "utf-8")
            )
            if passphrase
            else serialization.NoEncryption(),
        )

        # 6. instanciate objects
        pgp_private: PGPPrivateKey = PGPPrivateKey(
            _email=my_email,
            _name=name,
            _public_key=public_pem.decode(encoding="utf-8"),
            _user_id=str(my_email + ";" + name),
            _key_id=key_id_hex,
            _enc_private_key=private_pem.decode(encoding="utf-8"),
            _key_size=key_size,
        )

        return pgp_private

    def _extract_key_id_hex(self, public_number: int) -> str:
        mask = (1 << 64) - 1
        key_id = public_number & mask
        return f"{key_id: 016X}"
