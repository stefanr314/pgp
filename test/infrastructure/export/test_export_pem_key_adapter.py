import pytest
from unittest.mock import patch
from src.infrastructure.export.export_pem_key_adapter import ExportPEMKeyAdapter
from src.domain.exceptions import DiskWriteException


@pytest.fixture
def adapter():
    return ExportPEMKeyAdapter()


def test_export_key_adds_pem_extension(adapter: ExportPEMKeyAdapter, tmp_path):
    # Arrange: tmp_path is temp directory for holding files
    file_path = tmp_path / "moj_test_kljuc"  # without .pem
    test_data = "NEKI_PEM_STRING"

    # Act
    adapter.export_key(pem_data=test_data, filename=str(file_path))

    # Assert: File must have .pem extension
    expected_file = tmp_path / "moj_test_kljuc.pem"
    assert expected_file.exists()

    # assert the content of the file
    assert expected_file.read_text(encoding="utf-8") == test_data


def test_export_key_does_not_duplicate_pem_extension(
    adapter: ExportPEMKeyAdapter, tmp_path
):
    # Arrange: A file with .pem contained
    file_path = tmp_path / "vec_ima.pem"

    # Act
    adapter.export_key(pem_data="DATA", filename=str(file_path))

    # Assert: File must have correct name
    assert file_path.exists()


@patch("builtins.open")
def test_export_key_raises_disk_write_exception_on_ioerror(
    mock_open, adapter: ExportPEMKeyAdapter
):
    # Arrange: Simulate OS IO Error
    mock_open.side_effect = IOError("Permission denied")

    # Act & Assert: adapter translates to domain exception
    with pytest.raises(DiskWriteException):
        adapter.export_key(pem_data="DATA", filename="/zasticen_folder/test.pem")
