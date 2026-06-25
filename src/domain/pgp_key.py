from dataclasses import dataclass, field, replace
from datetime import datetime


@dataclass(frozen=True)
class PGPPrivateKey:
    _email: str
    _name: str
    _public_key: str
    _user_id: str
    _key_id: str
    _enc_private_key: str
    _key_size: int = 2048
    _deactivation_time: str | None = None
    _timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    _is_active: bool = True

    @property
    def email(self):
        return self._email

    @property
    def name(self):
        return self._name

    @property
    def public_key(self):
        return self._public_key

    @property
    def user_id(self):
        return self._user_id

    @property
    def enc_private_key(self) -> str:
        return self._enc_private_key

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def key_size(self):
        return self._key_size

    @property
    def is_active(self):
        return self._is_active

    def deactivate(self) -> "PGPPrivateKey":
        deactivated_at: str = datetime.now().isoformat()
        return replace(self, _deactivation_time=deactivated_at, _is_active=False)


@dataclass()
class PGPPublicKey:
    _user_id: str
    _key_id: str
    _public_key: str
    _owner_trust: float
    _key_legitimacy: float  # todo
    _signatures: list[str]
    _signature_trust: float
    _key_size: int = 2048
    _timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    _is_active: bool = True

    @property
    def key_id(self):
        return self._key_id

    @property
    def public_key(self):
        return self._public_key

    @property
    def user_id(self):
        return self._user_id

    @property
    def key_legitimacy(self):
        return self._key_legitimacy

    @property
    def key_size(self):
        return self._key_size

    @property
    def is_active(self):
        return self._is_active

    def deactivate(self):
        self._is_active = False
