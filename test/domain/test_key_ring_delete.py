import pytest
from unittest.mock import MagicMock
from src.domain.key_ring import KeyRing
from src.domain.exceptions import (
    KeyNotFoundException,
    UnauthorizedMethodInvocation
)

@pytest.fixture
def empty_keyring():
    return KeyRing()


def test_revoke_key_success(empty_keyring):
    # Arrange
    key_id = "moj_kljuc_123"
    
    mock_priv_key = MagicMock()
    mock_priv_key.key_id = key_id
    mock_priv_key.deactivate.return_value = "DEACTIVATED_PRIV_KEY"
    
    mock_pub_key = MagicMock()
    mock_pub_key.key_id = key_id
    
    empty_keyring.add_key_to_both_rings(mock_priv_key, mock_pub_key)
    
    # Act
    empty_keyring.revoke_key(key_id)
    
    # Assert
    # Provjeravamo da je privatni ključ zamijenjen deaktiviranom verzijom
    assert empty_keyring.get_my_private_key(key_id) == "DEACTIVATED_PRIV_KEY"
    # Provjeravamo da je javni ključ in-place deaktiviran
    mock_pub_key.deactivate.assert_called_once()

def test_revoke_key_not_found(empty_keyring):
    with pytest.raises(KeyNotFoundException):
        empty_keyring.revoke_key("nepostojeci_kljuc")

# --- Testovi za delete_foreign_public_key (Hard Delete) ---

def test_delete_foreign_public_key_success(empty_keyring):
    # Arrange
    key_id = "tudji_kljuc_456"
    mock_pub_key = MagicMock()
    mock_pub_key.key_id = key_id
    
    empty_keyring.add_key_to_public_ring(mock_pub_key)
    
    # Uvjerimo se da je ključ tu prije brisanja
    assert key_id in empty_keyring.public_ring
    
    # Act
    empty_keyring.delete_foreign_public_key(key_id)
    
    # Assert: Ključ mora biti potpuno uklonjen iz rječnika
    assert key_id not in empty_keyring.public_ring

def test_delete_foreign_public_key_not_found(empty_keyring):
    with pytest.raises(KeyNotFoundException):
        empty_keyring.delete_foreign_public_key("nepostojeci_kljuc")

def test_delete_foreign_public_key_unauthorized(empty_keyring):
    # Arrange: Ubacujemo ključ u OBA prstena (simuliramo naš lični ključ)
    key_id = "moj_licni_kljuc_789"
    
    mock_priv_key = MagicMock()
    mock_priv_key.key_id = key_id
    
    mock_pub_key = MagicMock()
    mock_pub_key.key_id = key_id
    
    empty_keyring.add_key_to_both_rings(mock_priv_key, mock_pub_key)
    
    # Act & Assert: Pokušaj brisanja našeg javnog ključa mora baciti grešku
    with pytest.raises(UnauthorizedMethodInvocation):
        empty_keyring.delete_foreign_public_key(key_id)
