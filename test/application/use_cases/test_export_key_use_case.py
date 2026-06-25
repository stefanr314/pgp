import pytest
from unittest.mock import MagicMock
from src.application.use_cases.export_key_use_case import ExportKeyUseCase
# Pretpostavka je da su KeyRing i ExportKeyPort ispravno importovani


@pytest.fixture
def mock_port():
    return MagicMock()


@pytest.fixture
def mock_keyring():
    # Mockujemo cijeli keyring da lakše kontrolišemo šta vraća
    keyring = MagicMock()
    keyring.export_public_key.return_value = "PUB_PEM_DATA"
    keyring.export_key_pair.return_value = "PRIV_PEM_DATA"
    return keyring


@pytest.fixture
def use_case(mock_keyring: MagicMock, mock_port: MagicMock):
    return ExportKeyUseCase(keyring=mock_keyring, export_key_port=mock_port)


def test_execute_exports_public_key_when_flag_is_true(
        use_case: ExportKeyUseCase, mock_keyring: MagicMock, mock_port: MagicMock
):
    # Act: Pozivamo sa public_only=True
    use_case.execute(filename="moj_kljuc", key_id="123", public_only=True)

    # Assert: Provjeravamo da je pozvana prava domenska metoda
    mock_keyring.export_public_key.assert_called_once_with("123")
    mock_keyring.export_key_pair.assert_not_called()

    # Provjeravamo da je port pozvan sa podacima iz javnog ključa
    mock_port.export_key.assert_called_once_with("PUB_PEM_DATA", "moj_kljuc")


def test_execute_exports_key_pair_when_flag_is_false(use_case, mock_keyring, mock_port):
    # Act: Pozivamo sa public_only=False (default)
    use_case.execute(filename="moj_kljuc", key_id="123", public_only=False)

    # Assert: Provjeravamo da je pozvana metoda za par ključeva
    mock_keyring.export_key_pair.assert_called_once_with("123")
    mock_keyring.export_public_key.assert_not_called()

    mock_port.export_key.assert_called_once_with("PRIV_PEM_DATA", "moj_kljuc")
