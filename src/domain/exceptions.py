from typing import final


class DomainException(Exception):
    """
    Base model for domain exceptions
    """

    pass


@final
class KeyAlreadyExistsException(DomainException):
    """
    Exception thrown when key ids match. Should not happend on regular uses.
    """

    def __init__(self, key_id: str) -> None:
        super().__init__(f"Key with {key_id} alredy exists.")
        self.key_id = key_id


@final
class InvalidFileFormatException(DomainException):
    """
    Exception thrown upon invalid file format
    """

    def __init__(self, filepath: str) -> None:
        super().__init__(f"Invalid file format on path={filepath}")
        self.__filepath = filepath


@final
class InvalidKeyFormatException(DomainException):
    """
    Exception thrown upon invalid PEM format of the keys
    """

    def __init__(self, keypath: str) -> None:
        super().__init__(f"Invalid format of key, on keypath: {keypath}")
        self.keypath = keypath


@final
class PasswordMismatchException(DomainException):
    """
    Exception thrown upon wrong password provided.
    """

    def __init__(self, filepath: str) -> None:
        super().__init__(f"Password mismatch on filepath: {filepath}")
        self.__filepath = filepath


@final
class InvalidPasswordRequirementException(DomainException):
    """
    Exception thrown when either password required but not provided, or provided but not required.
    """

    def __init__(self, filepath: str, message: str) -> None:
        super().__init__(f"{message}. On filepath: {filepath}")
        self.__filepath = filepath
        self.__message = message
