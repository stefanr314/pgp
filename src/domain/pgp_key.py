from dataclasses import dataclass, field, replace
from datetime import datetime


@dataclass(frozen=True)
class PGPPrivateKey:
    email: str
    name: str
    public_key: str
    user_id: str
    key_id: str
    enc_private_key: str
    key_size: int = 2048
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    is_active: bool = True

    def deactive(self) -> "PGPPrivateKey":
        return replace(self, is_active=False)


@dataclass()
class PGPPublicKey:
    user_id: str
    key_id: str
    public_key: str
    owner_trust: float
    key_legitimacy: float  # todo
    sigantures: list[str]
    signature_trust: float
    key_size: int = 2048
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
