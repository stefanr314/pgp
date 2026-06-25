from abc import ABC, abstractmethod


class ExportKeyPort(ABC):
    @abstractmethod
    def export_key(self, pem_data: str, filename: str) -> None:
        pass
