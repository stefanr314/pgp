import pytest
from unittest.mock import patch, mock_open
from cryptography.hazmat.primitives.asymmetric import rsa

from src.infrastructure.crypto.rsa_generator_adapter import RSAGeneratorAdapter
from src.domain.exceptions import (
    InvalidFileFormatException,
    InvalidKeyFormatException,
    InvalidPasswordRequirementException,
)
from src.domain.pgp_key import PGPPrivateKey, PGPPublicKey


@pytest.fixture
def adapter():
    return RSAGeneratorAdapter()


def test_generate_key_pair_returns_domain_models(adapter):
    """Testira da li generisanje vraća tačna dva domenska objekta"""
    priv, pub = adapter.generate_key_pair(
        name="Test User",
        email="test@example.com",
        key_size=1024,
        passphrase="mojalozinka",
    )

    assert isinstance(priv, PGPPrivateKey)
    assert isinstance(pub, PGPPublicKey)
    assert priv.email == "test@example.com"
    assert priv.key_id == pub.key_id  # Moraju imati isti ID


@patch("builtins.open", side_effect=FileNotFoundError)
def test_import_key_file_not_found(mock_file, adapter):
    """Testira prevođenje FileNotFoundError u domenski izuzetak"""
    with pytest.raises(InvalidFileFormatException):
        adapter.import_key(
            filepath="nepostojeci_fajl.pem",
            my_email="test@example.com",
            name="Test User",
        )


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data=b"Ovo nije PEM format smece podaci",
)
def test_import_key_invalid_header(mock_file, adapter):
    """Testira fajl koji nema PUBLIC ili PRIVATE u zaglavlju"""
    with pytest.raises(InvalidFileFormatException):
        adapter.import_key(
            filepath="fake.pem", my_email="test@example.com", name="Test User"
        )


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data=b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nsome_fake_base64_data",
)
def test_import_private_key_requires_passphrase_but_not_provided(mock_file, adapter):
    """
    Testira situaciju gde se traži privatni ključ, on je kriptovan,
    a mi nismo prosledili passphrase. `cryptography` baca ValueError,
    koji prevodimo u domenski.
    """
    # Ne moramo mockovati serialization jer će on pokušati da dekodira
    # 'some_fake_base64_data' bez lozinke i puknuće.
    with pytest.raises(InvalidKeyFormatException):
        adapter.import_key(
            filepath="fake_private.pem",
            my_email="test@example.com",
            name="Test User",
            passphrase=None,
        )


# Za potpun test privatnog ključa koji traži password, možemo mockovati i samu cryptography funkciju
@patch(
    "src.infrastructure.crypto.rsa_generator_adapter.serialization.load_pem_private_key"
)
@patch(
    "builtins.open", new_callable=mock_open, read_data=b"-----BEGIN PRIVATE KEY-----"
)
def test_import_private_key_raises_type_error_for_password(
    mock_file, mock_load, adapter
):
    """
    Simuliramo da `load_pem_private_key` baca TypeError (što radi kad fali password)
    """
    mock_load.side_effect = TypeError(
        "Password was not given but private key is encrypted"
    )

    with pytest.raises(InvalidPasswordRequirementException):
        adapter.import_key(
            filepath="fake_private.pem",
            my_email="test@example.com",
            name="Test User",
            passphrase=None,
        )
