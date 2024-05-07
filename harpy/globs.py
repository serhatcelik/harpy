"""This file contains globals."""

import threading
from typing import Any, Generic, TypeVar

controller = threading.Event()

interrupts = []  # type: list[Any]

_T = TypeVar('_T')


class Property(Generic[_T]):
    """Generic class implementing "get" and "set" methods."""

    def __init__(self, __value: _T) -> None:
        self.__value = __value

    def get(self) -> _T:
        """Get value."""
        return self.__value

    def set(self, __value: _T) -> None:
        """Set value."""
        self.__value = __value


sent = Property('')  # type: Property[str]
