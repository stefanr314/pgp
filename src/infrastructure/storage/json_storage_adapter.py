from dataclasses import dataclass
import json

from src.domain.pgp_key import PGPPrivateKey, PGPPublicKey


@dataclass
class JSONPrivateKeyringAdapter:
    """
    Adapter for working with json files stored keys
    """

    file_path: str

    def save_data(self, data: dict[str, PGPPrivateKey]) -> None:
        raw_data = {k: v.__dict__ for k, v in data.items()}
        with open(self.file_path, "w") as file_obj:
            json.dump(raw_data, file_obj, indent=4)

    def load_data(self) -> dict[str, PGPPrivateKey]:
        """
        Method for reaching the key structure stored locally in json file.
        """
        try:
            with open(self.file_path, encoding="utf-8") as ringjson:
                raw_data = json.load(ringjson)

        except FileNotFoundError:
            content: dict[str, PGPPrivateKey] = {}
            self.save_data(content)
            return content
        except json.JSONDecodeError as e:
            print(e)
            return {}

        else:
            obj_dict: dict[str, PGPPrivateKey] = {
                k: PGPPrivateKey(**raw_data[k]) for k in raw_data
            }
            return obj_dict


@dataclass()
class JSONPublicKeyringAdapter:
    """
    Adapter for working with json files stored keys
    """

    file_path: str

    def save_data(self, data: dict[str, PGPPublicKey]) -> None:
        raw_data = {k: v.__dict__ for k, v in data.items()}
        with open(self.file_path, "w") as file_obj:
            json.dump(raw_data, file_obj, indent=4)

    def load_data(self) -> dict[str, PGPPublicKey]:
        """
        Method for reaching the key structure stored locally in json file.
        """
        try:
            with open(self.file_path, encoding="utf-8") as ringjson:
                raw_data = json.load(ringjson)

        except FileNotFoundError:
            content: dict[str, PGPPublicKey] = {}
            self.save_data(content)
            return content
        except json.JSONDecodeError as e:
            print(e)
            return {}

        else:
            obj_dict: dict[str, PGPPublicKey] = {
                k: PGPPublicKey(**raw_data[k]) for k in raw_data
            }
            return obj_dict


if __name__ == "__main__":
    pass
