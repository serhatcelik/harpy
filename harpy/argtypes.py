"""Custom argument types."""

import argparse
import ipaddress


def device(name: str) -> str:
    """Network device."""
    if not name:
        raise argparse.ArgumentTypeError('no available network devices')
    return name


def ipv4(address: str) -> ipaddress.IPv4Network:
    """IPv4 network."""
    try:
        return ipaddress.IPv4Network(address, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as err:
        raise argparse.ArgumentTypeError(err)
