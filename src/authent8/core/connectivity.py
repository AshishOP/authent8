"""Connectivity checks for scan runtime decisions."""

import socket


def has_internet(timeout: float = 2.5) -> bool:
    """Fast internet check using a DNS endpoint."""
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=timeout)
        return True
    except OSError:
        return False
