#
# Helper functions for EJBCA submodules
#

import os
import sys

from typing import Tuple, Optional, Union

import urllib3

import urllib.parse as parse

import datetime
import json

import ejbca

iso8601_fmt = '%Y-%m-%dT%H:%M:%SZ'

def eprint(*args, **kwargs) -> None:
    print(*args, file = sys.stderr, **kwargs)

def dump(req: urllib3.response.HTTPResponse) -> None:
    eprint('{0:d} {1:s}\n'.format(req.status, req.reason))
    ##for hdr in req.headers:
    ##    eprint('{0:s}: {1:s}'.format(hdr, req.headers[hdr]))
    eprint(req.data.decode())

def parse_ts(timestamp: str) -> datetime.datetime:
     return datetime.datetime.strptime(timestamp, iso8601_fmt)

def quote(s: bytes) -> bytes:
    return parse.quote_from_bytes(s, safe = '').encode()

def quote(s: str) -> str:
    return parse.quote(s, safe = '')

def unquote(s: bytes) -> bytes:
    return parse.unquote_to_bytes(s)

def unquote(s: str) -> str:
    return parse.unquote(s)

def localurl(url: str) -> str:
    u = parse.urlparse(url)
    s = u[2]
    if u[3] != "":
       s += ';' + u[3]
    if u[4] != "":
       s += '?' + u[4]
    if u[5] != "":
       s += '#' + u[5]
    return s

