from typing import final


class DomainException(Exception):
    """
    Base model for domain exceptions
    """

    pass


@final
class UnauthorizedMethodInvocation(DomainException):
    """
    Exception thrown upon trying to delete key using the wrong method call.
    Used when key is in private ring but tried to be delete from public delete_foreign_public_key
    method.
    """

    def __init__(self, key_id: str) -> None:
        super().__init__(f"Unauthorized method call on key with id={key_id}")
        self._key_id = key_id


@final
class DiskWriteException(DomainException):
    """
    Exception thrown upon invalid disk write operation
    """

    def __init__(self, filename: str) -> None:
        super().__init__(f"Disk write corruption on path={filename}")
        self._filename = filename


@final
class KeyAlreadyExistsException(DomainException):
    """
    Exception thrown when key ids match. Should not happend on regular uses.
    """

    def __init__(self, key_id: str) -> None:
        super().__init__(f"Key with {key_id} alredy exists.")
        self._key_id = key_id


@final
class KeyNotFoundException(DomainException):
    """
    Exception thrown when provided key id was not found in ring.
    """

    def __init__(self, key_id: str) -> None:
        super().__init__(f"Key not found in ring. Key id = {key_id}")
        self._key_id = key_id


@final
class InvalidFileFormatException(DomainException):
    """
    Exception thrown upon invalid file format
    """

    def __init__(self, filepath: str) -> None:
        super().__init__(f"Invalid file format on path={filepath}")
        self._filepath = filepath


@final
class InvalidKeyFormatException(DomainException):
    """
    Exception thrown upon invalid PEM format of the keys
    """

    def __init__(self, keypath: str) -> None:
        super().__init__(f"Invalid format of key, on keypath: {keypath}")
        self._keypath = keypath


@final
class PasswordMismatchException(DomainException):
    """
    Exception thrown upon wrong password provided.
    """

    def __init__(self, filepath: str) -> None:
        super().__init__(f"Password mismatch on filepath: {filepath}")
        self._filepath = filepath


@final
class InvalidPasswordRequirementException(DomainException):
    """
    Exception thrown when either password required but not provided, or provided but not required.
    """

    def __init__(self, filepath: str, message: str) -> None:
        super().__init__(f"{message}. On filepath: {filepath}")
        self._filepath = filepath
        self._message = message
