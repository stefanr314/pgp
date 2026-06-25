import pytest
from unittest.mock import MagicMock
from src.application.use_cases.delete_foreign_public_key_use_case import (
    DeleteForeignPublicKeyUseCase,
)
from src.application.use_cases.delete_key_pair_use_case import DeleteKeyPairUseCase


@pytest.fixture
def mock_keyring():
    return MagicMock()


@pytest.fixture
def mock_repo():
    return MagicMock()


# --- Test za DeleteKeyPairUseCase ---


def test_delete_key_pair_use_case_orchestration(mock_keyring, mock_repo):
    # Arrange
    use_case = DeleteKeyPairUseCase(keyring=mock_keyring, keyring_repo=mock_repo)
    key_id = "123"

    # Act
    use_case.execute(key_id)

    # Assert
    # 1. Da li je okinuo revoke na domenu?
    mock_keyring.revoke_key.assert_called_once_with(key_id)
    # 2. Da li je sačuvao OBA prstena (save_all)?
    mock_repo.save_all.assert_called_once_with(keyring=mock_keyring)


# --- Test za DeleteForeignPublicKeyUseCase ---


def test_delete_foreign_public_key_use_case_orchestration(mock_keyring, mock_repo):
    # Arrange
    use_case = DeleteForeignPublicKeyUseCase(
        keyring=mock_keyring, keyring_repo=mock_repo
    )
    key_id = "456"

    # Act
    use_case.execute(key_id)

    # Assert
    # 1. Da li je okinuo brisanje tudjeg ključa na domenu?
    mock_keyring.delete_foreign_public_key.assert_called_once_with(key_id)
    # 2. Da li je sačuvao SAMO public ring (save_public)?
    mock_repo.save_public.assert_called_once_with(mock_keyring)
