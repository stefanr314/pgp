from src.application.out.export_key_port import ExportKeyPort
from src.domain.key_ring import KeyRing


class ExportKeyUseCase:
    _keyring: KeyRing
    _export_key_port: ExportKeyPort

    def __init__(self, keyring: KeyRing, export_key_port: ExportKeyPort) -> None:
        self._keyring = keyring
        self._export_key_port = export_key_port

    def execute(self, filename: str, key_id: str, public_only: bool = False):
        if public_only:
            pem_data: str = self._keyring.export_public_key(key_id)
        else:
            pem_data = self._keyring.export_key_pair(key_id)

        self._export_key_port.export_key(pem_data, filename)
