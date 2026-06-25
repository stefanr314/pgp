from typing import override

from src.application.out.export_key_port import ExportKeyPort
from src.domain.exceptions import DiskWriteException


class ExportPEMKeyAdapter(ExportKeyPort):
    @override
    def export_key(self, pem_data: str, filename: str) -> None:
        if not filename.lower().endswith(".pem"):
            filename += ".pem"

        try:
            with open(file=filename, mode="w", encoding="utf-8") as export_location:
                _ = export_location.write(pem_data)

        except IOError as e:
            raise DiskWriteException(filename) from e
