#!/usr/bin/env python

# Copyright (c) 2014 v3aqb
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
import socket
import select
from repoze.lru import lru_cache


@lru_cache(4096, timeout=90)
def getaddrinfo(host, port=None, family=0, socktype=0, proto=0, flags=0):
    """return (family, socktype, proto, canonname, sockaddr)
       >>> socket.getaddrinfo("www.python.org", 80, 0, 0, socket.SOL_TCP)
       [(2, 1, 6, '', ('82.94.164.162', 80)),
        (10, 1, 6, '', ('2001:888:2000:d::a2', 80, 0, 0))]"""
    return socket.getaddrinfo(host, port, family, socktype, proto, flags)


def create_connection(address, timeout=object(), source_address=None):
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    An host of '' or port 0 tells the OS to use the default.
    """

    host, port = address
    err = None
    for res in getaddrinfo(host, port):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not object():
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock

        except socket.error as _:
            err = _
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


def is_connection_dropped(sock):  # from urllib3
    """
    Returns True if the connection is dropped and should be closed.

    """
    if not hasattr(select, 'poll'):
        try:
            return select.select([sock], [], [], 0.0)[0]
        except socket.error:
            return True
    # This version is better on platforms that support it.
    p = select.poll()
    p.register(sock, select.POLLIN)
    for (fno, ev) in p.poll(0.0):
        if fno == sock.fileno():
            # Either data is buffered (bad), or the connection is dropped.
            return True


if __name__ == "__main__":
    t = socket.getaddrinfo('www.baidu.com', 80)
    r = getaddrinfo('www.baidu.com')
    print(t)
    print(r)
    print(r[0][4][0])
