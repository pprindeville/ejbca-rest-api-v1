#
# init hooks for ejbca library
#

import os
import sys

from typing import Tuple, Optional, Union

tracing = False

class Creds:

    __slots__ = ['_secure', '_bundle', '_cert', '_key']

    def __checkfile(path: bytes) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError('File not found', path)

    def __init__(
            self,
            secure: bool = False,
            bundle: Optional[bytes] = None,
            cert: Optional[bytes] = None,
            key: Optional[bytes] = None,
        ):
        self._secure = secure
        if not bundle is None:
            Creds.__checkfile(bundle)
        self._bundle = bundle
        if not cert is None:
            Creds.__checkfile(cert)
        self._cert = cert
        if not key is None:
            Creds.__checkfile(key)
        self._key = key

    def dump(self):
        print('_secure: {0:b}'.format(self._secure))
        print('_bundle: {0:s}'.format(self._bundle))
        print('_cert: {0:s}'.format(self._cert))
        print('_key: {0:s}'.format(self._key))

    @property
    def secure(self) -> bool:
        return self._secure

    @secure.setter
    def secure(self, value: bool) -> None:
        self._secure = value

    @property
    def bundle(self) -> bytes:
        return self._bundle

    @bundle.setter
    def bundle(self, value: Union[bytes, None]) -> None:
        self._bundle = value

    @property
    def cert(self) -> bytes:
        return self._cert

    @cert.setter
    def cert(self, value: Union[bytes, None]) -> None:
        self._cert = value

    @property
    def key(self) -> bytes:
        return self._key

    @key.setter
    def key(self, value: Union[bytes, None]) -> None:
        self._key = value

class Server:

    __slots__ = ['_name', '_alias']

    def __init__(self, name: str):
        self._name = name
        self._alias = 'est'

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        self._name = name

    @property
    def alias(self) -> str:
        return self._alias

    @alias.setter
    def alias(self, alias: str) -> None:
        self._alias = alias

server = Server('ca.primekey.se')

from .rest import getcert, getcertstatus, add_end_entity, delete_end_entity, enroll_keystore

from .est import simple_enroll, ca_certs

from .ocsp import getocspstatus

from .certstore import search_subject

__all__ = [
    'Creds',
    'Server',
    'server',
    'tracing',
    'getcert',
    'getcertstatus',
    'add_end_entity',
    'delete_end_entity',
    'enroll_keystore',
    'simple_enroll',
    'ca_certs',
    'getocspstatus',
    'search_subject',
]

