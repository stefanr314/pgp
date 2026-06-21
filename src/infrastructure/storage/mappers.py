from src.domain.pgp_key import PGPPrivateKey


JSONValue = str | int | bool  # Python 3.10+


class PrivateKeyMapper:
    @staticmethod
    def to_json_dict(key: PGPPrivateKey) -> dict[str, JSONValue]:
        """Pretvara čisti domen objekat u rečnik spreman za JSON."""
        return {
            "email": key.email,
            "name": key.name,
            "user_id": key.user_id,
            "key_id": key.key_id,
            "enc_private_key": key.enc_private_key,
            "public_key": key.public_key,
            "key_size": key.key_size,
            "timestamp": key.timestamp,
            "is_active": key.is_active,
        }

    @staticmethod
    def to_domain(data: dict[str, JSONValue]) -> PGPPrivateKey:
        """Uzima sirovi rečnik iz JSON-a i pravi čist domenski objekat."""
        return PGPPrivateKey(
            email=str(data["email"]),
            name=str(data["name"]),
            user_id=str(data["user_id"]),
            key_id=str(data["key_id"]),
            enc_private_key=str(data["enc_private_key"]),
            public_key=str(data["public_key"]),
            key_size=int(data["key_size"]),
            timestamp=str(data["timestamp"]),
            is_active=bool(data["is_active"]),
        )
