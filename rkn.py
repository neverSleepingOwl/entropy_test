#!/usr/bin/python3

import re

from typing import List

# I thought that using ipaddress library would be unfair.

number_regexp = r'([1-9](?:\d?){2}|0)'  # regexp to parse numbers in range [0-999]

ip_parsing_regexp = r'\.'.join([number_regexp] * 4) + r'(?:\/([1-9]\d?))?'
ip_parsing_matcher = re.compile(ip_parsing_regexp)
mask_range = range(1, 33)  # |
ip_range = range(0, 256)   # | => in python3 check if blah in range(a,b) works with O(1) time complexity


class RKNBlockError(Exception):
    def __init__(self, message):
        super().__init__(self, message)
        self.message = message

    def __str__(self):
        return self.message + (" : " + str(self.__cause__) if self.__cause__ else "")


def parse_ip(parsed_ip_address: List[int]) -> int:
    try:
        ip = 0
        if len(parsed_ip_address) not in range(4, 6):
            raise RKNBlockError("Incorrect ip address processed, however parsing was successfull. Internal error")
            # Heard somewhere that builtin exceptions are better, but i still use custom ones.
            # change my mind:)

        for i, element in enumerate(parsed_ip_address[0:4]):
            if element not in ip_range:
                raise RKNBlockError("IP must be in format a.b.c.d where a,b,c,d digits in [0-255].")
            ip |= element << (3 - i) * 8  # find binary ip address
        return ip
    except (AttributeError, ValueError) as err:
        raise RKNBlockError("Incorrect parsed ip processing.") from err


def get_netmask(parsed_ip_address: List[int]) -> int:
    try:
        netmask = parsed_ip_address[4]  # temporary variable for storing netmask as number
        if netmask not in mask_range:
            raise RKNBlockError("Netmask must be in [1-32] not {0}".format(netmask))
        return netmask
    except IndexError as err:
        raise RKNBlockError("Incorrect index access, this ip doesn't have a mask.") from err


def parse_addresses(ip_addr: str) -> List[int]:
    try:
        # ip.ip.ip.ip/mask -> ip, ip, ip, ip, mask
        return [int(i) for i in re.match(ip_parsing_matcher, ip_addr).groups() if i is not None]
    except (AttributeError, ValueError, TypeError) as err:
        raise RKNBlockError("Error while parsing ip addres : {0}".format(ip_addr)) from err


class Ip:
    def __init__(self, ip_address: str, masked=True):
        ip_parsed = parse_addresses(ip_address)
        if masked:
            self._mask = get_netmask(ip_parsed)
        else:
            self._mask = 0
        self._ip = parse_ip(ip_parsed)

    def __hash__(self):
        tmp = self._ip
        tmp = tmp >> (32 - self._mask)
        tmp = tmp << (32 - self._mask)
        return tmp

    def __eq__(self, other):
        # eq and hash must
        #  return the same values for set method __contains__ return true if hashes are the same
        return self.__hash__() == other.__hash__()

    def set_mask(self, mask: int):
        if mask not in mask_range:
            raise RKNBlockError("Netmask '{0}' is not in [1-32]".format(mask))
        self._mask = mask

    def get_mask(self):
        return self._mask

    #  Don't remember, how to use decorators for properties
    mask = property(fget=get_mask, fset=set_mask)


class RKN:
    def __init__(self, addresses: List[str]):
        self._storage = {i: set() for i in mask_range}
        for address in addresses:
            addr = Ip(address)
            self._storage[addr.mask].add(addr)

    def __contains__(self, item):
        addr = Ip(item, masked=False)
        # Time complexity is O(1)
        for i in mask_range:
            addr.mask = i
            if addr in self._storage[i]:
                return True
        return False

    def is_banned(self, item):
        return item in self


if __name__ == "__main__":
    r = RKN(['10.0.0.0/8', '8.8.8.8/32'])
    print(r.is_banned('10.1.2.3'))  # True
    print(r.is_banned('127.0.0.1'))  # False
    print(r.is_banned('8.8.8.8'))  # True
    print(r.is_banned('8.8.8.7'))  # False
