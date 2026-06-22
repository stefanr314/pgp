from typing import override, Literal
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from src.application.out.crypto_service_port import CryptoServicePort
from src.domain.exceptions import InvalidKeyFormatException
from src.domain.pgp_key import PGPPrivateKey, PGPPublicKey


class CryptoEngineAdapter(CryptoServicePort):
    @override
    def generate_key_pair(
        self, name: str, email: str, key_size: Literal[1024, 2048], passphrase: str
    ) -> tuple[PGPPrivateKey, PGPPublicKey]:
        # 1. generate private and public rsa key parts
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        public_key = private_key.public_key()

        # 2. key_id mod 2^64
        public_number: int = public_key.public_numbers().n

        mask = (1 << 64) - 1
        key_id: int = public_number & mask
        key_id_hex: str = f"{key_id:016X}"

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
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                bytes(passphrase, "utf-8")
            ),
        )

        # 6. instanciate objects
        pgp_private: PGPPrivateKey = PGPPrivateKey(
            email=email,
            name=name,
            public_key=public_pem.decode(encoding="utf-8"),
            user_id=str(email + ";" + name),
            key_id=key_id_hex,
            enc_private_key=private_pem.decode(encoding="utf-8"),
            key_size=key_size,
        )

        pgp_public: PGPPublicKey = PGPPublicKey(
            user_id=email,
            key_id=key_id_hex,
            public_key=public_pem.decode("utf-8"),
            owner_trust=1.0,
            key_legitimacy=1.0,
            signatures=list(),
            signature_trust=0.0,
            key_size=key_size,
        )

        # 7. return keys
        return pgp_private, pgp_public

    @override
    def import_public_key(self, filepath: str, email: str) -> PGPPublicKey:
        # use the method to load the key
        try:
            with open(file=filepath, mode="rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

        except (ValueError, UnsupportedAlgorithm) as e:
            raise InvalidKeyFormatException(filepath) from e
        else:
            if isinstance(public_key, rsa.RSAPublicKey):
                mask = (1 << 64) - 1
                key_id: int = public_key.public_numbers().n & mask
                key_id_hex: str = f"{key_id:016X}"

                key_size = public_key.key_size

                pgp_raw = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                pgp_public: PGPPublicKey = PGPPublicKey(
                    user_id=email,
                    key_id=key_id_hex,
                    public_key=pgp_raw.decode("utf-8"),
                    owner_trust=1.0,
                    key_legitimacy=1.0,
                    signatures=list(),
                    signature_trust=0.0,
                    key_size=key_size,
                )

                return pgp_public
            else:
                # just support rsa keys currently
                raise InvalidKeyFormatException(filepath)

    @override
    def import_key_pair(
        self, filepath_private_key: str, filepath_public_key: str, my_email: str
    ):
        return super().import_key_pair(filepath_private_key, filepath_public_key)
