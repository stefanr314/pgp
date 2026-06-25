import pytest
from unittest.mock import MagicMock
from src.domain.key_ring import KeyRing
from src.domain.exceptions import KeyNotFoundException


@pytest.fixture
def empty_keyring():
    return KeyRing()


def test_export_public_key_success(empty_keyring: KeyRing):
    # Arrange 
    mock_pub_key = MagicMock()
    mock_pub_key.key_id = "pub_123"
    mock_pub_key.public_key = "-----BEGIN PUBLIC KEY-----\n..."

    empty_keyring.add_key_to_public_ring(mock_pub_key)

    # Act
    result = empty_keyring.export_public_key("pub_123")

    # Assert
    assert result == "-----BEGIN PUBLIC KEY-----\n..."


def test_export_public_key_not_found(empty_keyring: KeyRing):
    # Act & Assert
    with pytest.raises(KeyNotFoundException):
        _ = empty_keyring.export_public_key("fake_id")


def test_export_key_pair_success(empty_keyring: KeyRing):
    # Arrange 
    mock_priv_key = MagicMock()
    mock_priv_key.key_id = "priv_123"
    mock_priv_key.enc_private_key = "-----BEGIN PRIVATE KEY-----\n..."

    empty_keyring.add_key_to_private_ring(mock_priv_key)

    # Act
    result = empty_keyring.export_key_pair("priv_123")

    # Assert
    assert result == "-----BEGIN PRIVATE KEY-----\n..."


def test_export_key_pair_not_found(empty_keyring: KeyRing):
    with pytest.raises(KeyNotFoundException):
        _ = empty_keyring.export_key_pair("fake_id")
