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
class InvalidKeyFormatException(DomainException):
    """
    Exception for cathcing invalid PEM format of the keys
    """

    def __init__(self, keypath: str) -> None:
        super().__init__(f"Invalid format of key, on keypath: {keypath}")
        self.keypath = keypath
