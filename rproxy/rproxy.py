#!/usr/bin/env python2.7
#-*- coding: UTF-8 -*-
#
# rproxy.py A Reverse Proxy Server work with shadowsocks
#
# Copyright (C) 2012-2014 Jiang Chao <sgzz.cj@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses>.

from __future__ import print_function

__version__ = '1.0'

import sys
import os

sys.dont_write_bytecode = True
WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
if ' ' in WORKINGDIR:
    sys.stderr.write('no spacebar allowed in path\n')
    sys.exit(-1)
os.chdir(WORKINGDIR)
sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')))
gevent = None
try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    pass
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('Warning: Please update gevent to the latest 1.0 version!\n')
from collections import defaultdict, deque
import subprocess
import shlex
import time
import re
import errno
import email
import base64
import logging
import random
import select
import shutil
import socket
import struct
import ssl
try:
    from cStringIO import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io import BytesIO as StringIO
from threading import Thread
from repoze.lru import lru_cache
import encrypt
from util import create_connection, getaddrinfo, parse_hostport, is_connection_dropped
try:
    import configparser
    import urllib.request as urllib2
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    from socketserver import ThreadingMixIn
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from ipaddress import ip_address
except ImportError:
    import urllib2
    import urlparse
    urlquote = urllib2.quote
    import ConfigParser as configparser
    from SocketServer import ThreadingMixIn
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from ipaddr import IPAddress as ip_address
configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')

logging.basicConfig(level=logging.INFO,
                    format='rproxy %(asctime)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S', filemode='a+')

if sys.platform.startswith('win'):
    PYTHON2 = '%s/Python27/python27.exe' % WORKINGDIR
else:
    for cmd in ('python2.7', 'python27', 'python2'):
        if subprocess.call(shlex.split('which %s' % cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            PYTHON2 = cmd
            break
PYTHON = sys.executable.replace('\\', '/')

NetWorkIOError = (socket.error, ssl.SSLError, OSError)


def prestart():
    s = 'rproxy ' + __version__
    if gevent:
        s += ' with gevent %s' % gevent.__version__
    logging.info(s)

    if not os.path.isfile('./userconf.ini'):
        shutil.copyfile('./userconf.sample.ini', './userconf.ini')

    if not os.path.isfile('./rproxy/local.txt'):
        with open('./rproxy/local.txt', 'w') as f:
            f.write('''
! local gfwlist config
! rules: https://autoproxy.org/zh-CN/Rules
! /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1/
''')

prestart()


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class HTTPCONN_POOL(object):
    POOL = defaultdict(deque)
    lastactive = {}

    @classmethod
    def put(cls, upstream_name, soc, ppname):
        cls.lastactive[soc.fileno()] = time.time()
        cls.POOL[upstream_name].append((soc, ppname))

    @classmethod
    def get(cls, upstream_name):
        lst = cls.POOL.get(upstream_name)
        while lst:
            sock, pproxy = lst.popleft()
            if not is_connection_dropped(sock):
                return (sock, pproxy)
            sock.close()

    @classmethod
    def purge(cls):
        pcount = count = 0
        for k, v in cls.POOL.items():
            count += len(v)
            try:
                for i in [pair for pair in v if (pair[0] in select.select([item[0] for item in v], [], [], 0.0)[0]) or (cls.lastactive[pair[0].fileno()] < time.time() - 300)]:
                    v.remove(i)
                    pcount += 1
            except Exception as e:
                logging.warning('Exception caught in purge! %r' % e)
        count -= pcount
        if pcount or count:
            logging.info('%d remotesoc purged, %d in connection pool.(%s)' % (pcount, count, ', '.join([k[0] if isinstance(k, tuple) else k for k, v in cls.POOL.items() if v])))


class HTTPRequestHandler(BaseHTTPRequestHandler):
    def _quote_html(self, html):
        return html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header('Connection', 'keep_alive')
        self.send_header("Content-Length", '0')
        self.end_headers()

    def log_message(self, format, *args):
        pass

    def finish(self):
        """make python2 BaseHTTPRequestHandler happy"""
        try:
            BaseHTTPRequestHandler.finish(self)
        except (IOError, OSError) as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def send_error(self, code, message=None):
        """Send and log an error reply. """
        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        # using _quote_html to prevent Cross Site Scripting attacks (see bug #1100201)
        content = (self.error_message_format %
                   {'code': code, 'message': self._quote_html(message), 'explain': explain})
        self.send_response(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Connection', 'keep_alive')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(content)

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            s = "%s %d %s\r\n" % (self.protocol_version, code, message)
            self.wfile.write(s.encode())
        self.send_header('ProxyServer', self.version_string())
        self.send_header('Date', self.date_time_string())

    def _request_localhost(self, req):
        try:
            return ip_address(getaddrinfo(req[0], req[1])[0][4][0]).is_loopback
        except Exception as e:
            logging.error(repr(e))


class ProxyHandler(HTTPRequestHandler):
    server_version = "rproxy/" + __version__
    protocol_version = "HTTP/1.1"
    bufsize = 8192
    timeout = 10
    ssrealip = None
    ssclient = ''

    def handle_one_request(self):
        self._proxylist = None
        self.remotesoc = None
        self.retryable = True
        self.rbuffer = deque()  # client read buffer: store request body, ssl handshake package for retry. no pop method.
        self.wbuffer = deque()  # client write buffer: read only once, not used in connect method
        self.wbuffer_size = 0
        self.shortpath = None
        self.failed_parents = []
        try:
            HTTPRequestHandler.handle_one_request(self)
        except socket.error as e:
            if e.errno in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                self.close_connection = 1
            else:
                raise
        if self.remotesoc:
            self.remotesoc.close()

    def _getparent(self, level=1):
        if self._proxylist is None:
            self._proxylist = PARENT_PROXY.parentproxy(self.path, self.requesthost, self.command, level)
            logging.debug(repr(self._proxylist))
        if not self._proxylist:
            self.ppname = ''
            return 1
        self.ppname = self._proxylist.pop(0)
        self.pproxy = conf.parentdict.get(self.ppname)[0]
        self.pproxyparse = urlparse.urlparse(self.pproxy)

    def getparent(self, level=1):
        return self._getparent(level)

    def do_GET(self):
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self.path.lower().startswith('ftp://'):
            return self.send_error(504)
        # transparent proxy
        if self.path.startswith('/') and 'Host' in self.headers:
            self.path = 'http://%s%s' % (self.headers['Host'], self.path)
        if self.path.startswith('/'):
            return self.send_error(403)
        # redirector
        new_url = REDIRECTOR.get(self.path)
        if new_url:
            logging.debug('redirecting to %s' % new_url)
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                return self.send_error(int(new_url))
            elif new_url in conf.parentdict.keys():
                self._proxylist = [new_url]
            else:
                return self.redirect(new_url)

        if 'Host' not in self.headers:
            self.headers['Host'] = urlparse.urlparse(self.path).netloc

        if 'ss-realip' in self.headers:  # should exist in first request only
            self.ssrealip = self.headers['ss-realip']
        del self.headers['ss-realip']

        if 'ss-client' in self.headers:  # should exist in first request only
            self.ssclient = self.headers['ss-client']
        del self.headers['ss-client']

        self.requesthost = parse_hostport(self.headers['Host'], 80)

        if self._request_localhost(self.requesthost):
            if ip_address(self.client_address[0]).is_loopback and self.requesthost[1] in (conf.listen[1], conf.listen[1] + 1):
                self.send_response(200)
                msg = 'Hello World !'
                self.send_header('Content-type', 'text/html')
                self.send_header('Content-Length', str(len(msg)))
                self.send_header('Connection', 'keep_alive')
                self.end_headers()
                # Send the html message
                self.wfile.write(msg)
                return
            if not ip_address(self.client_address[0]).is_loopback:
                return self.send_error(403)
        self.shortpath = '%s%s' % (self.path.split('?')[0], '?' if len(self.path.split('?')) > 1 else '')

        if conf.xheaders and self.ssrealip:
            ipl = [ip.strip() for ip in self.headers.get('X-Forwarded-For', '').split(',') if ip.strip()]
            ipl.append(self.ssrealip)
            self.headers['X-Forwarded-For'] = ', '.join(ipl)

        self._do_GET()

    def _do_GET(self, retry=False):
        if retry:
            if self.remotesoc:
                self.remotesoc.close()
                self.remotesoc = None
            self.failed_parents.append(self.ppname)
        if not self.retryable:
            self.close_connection = 1
            PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, False, self.failed_parents, self.ppname)
            return
        if self.getparent():
            PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, False, self.failed_parents, self.ppname)
            return self.send_error(504)

        self.upstream_name = self.ppname if self.pproxy.startswith('http') else self.requesthost
        try:
            self.remotesoc = self._http_connect_via_proxy(self.requesthost)
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        self.wbuffer = deque()
        self.wbuffer_size = 0
        # send request header
        logging.debug('sending request header')
        s = []
        if self.pproxy.startswith('http'):
            s.append('%s %s %s\r\n' % (self.command, self.path, self.request_version))
            if self.pproxyparse.username:
                a = '%s:%s' % (self.pproxyparse.username, self.pproxyparse.password)
                self.headers['Proxy-Authorization'] = 'Basic %s' % base64.b64encode(a.encode())
        else:
            s.append('%s /%s %s\r\n' % (self.command, '/'.join(self.path.split('/')[3:]), self.request_version))
        del self.headers['Proxy-Connection']
        for k, v in self.headers.items():
            if isinstance(v, bytes):
                v = v.decode('latin1')
            s.append("%s: %s\r\n" % ("-".join([w.capitalize() for w in k.split("-")]), v))
        s.append("\r\n")
        try:
            self.remotesoc.sendall(''.join(s).encode('latin1'))
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        logging.debug('sending request body')
        # send request body
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length:
            if content_length > 102400:
                self.retryable = False
            if self.rbuffer:
                s = b''.join(self.rbuffer)
                content_length -= len(s)
                try:
                    self.remotesoc.sendall(s)
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
            while content_length:
                data = self.rfile.read(min(self.bufsize, content_length))
                if not data:
                    break
                content_length -= len(data)
                if self.retryable:
                    self.rbuffer.append(data)
                try:
                    self.remotesoc.sendall(data)
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
        # read response line
        logging.debug('reading response_line')
        remoterfile = self.remotesoc if hasattr(self.remotesoc, 'readline') else self.remotesoc.makefile('rb', 0)
        try:
            s = response_line = remoterfile.readline()
            if not s.startswith(b'HTTP'):
                raise OSError(0, 'bad response line: %r' % response_line)
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        protocol_version, _, response_status = response_line.rstrip(b'\r\n').partition(b' ')
        response_status, _, response_reason = response_status.partition(b' ')
        response_status = int(response_status)
        # read response headers
        logging.debug('reading response header')
        header_data = []
        try:
            while True:
                line = remoterfile.readline()
                header_data.append(line)
                if line in (b'\r\n', b'\n', b''):  # header ends with a empty line
                    break
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        header_data = b''.join(header_data)
        response_header = email.message_from_string(header_data)
        conntype = response_header.get('Connection', "")
        if protocol_version >= b"HTTP/1.1":
            self.close_connection = conntype.lower() == 'close'
        else:
            self.close_connection = conntype.lower() != 'keep_alive'
        logging.debug('reading response body')
        if "Content-Length" in response_header:
            if "," in response_header["Content-Length"]:
                # Proxies sometimes cause Content-Length headers to get
                # duplicated.  If all the values are identical then we can
                # use them but if they differ it's an error.
                pieces = re.split(r',\s*', response_header["Content-Length"])
                if any(i != pieces[0] for i in pieces):
                    raise ValueError("Multiple unequal Content-Lengths: %r" %
                                     response_header["Content-Length"])
                response_header["Content-Length"] = pieces[0]
            content_length = int(response_header["Content-Length"])
        else:
            content_length = None
        self.wfile_write(s)
        self.wfile_write(header_data)
        # read response body
        if self.command == 'HEAD' or 100 <= response_status < 200 or response_status in (204, 304):
            pass
        elif response_header.get("Transfer-Encoding") and response_header.get("Transfer-Encoding") != "identity":
            flag = 1
            while flag:
                try:
                    trunk_lenth = remoterfile.readline()
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
                self.wfile_write(trunk_lenth)
                trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                flag = trunk_lenth != 2
                while trunk_lenth:
                    try:
                        data = self.remotesoc.recv(min(self.bufsize, trunk_lenth))
                    except NetWorkIOError as e:
                        return self.on_GET_Error(e)
                    trunk_lenth -= len(data)
                    self.wfile_write(data)
        elif content_length is not None:
            while content_length:
                try:
                    data = self.remotesoc.recv(min(self.bufsize, content_length))
                    if not data:
                        raise OSError(0, 'socket read empty')
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
                content_length -= len(data)
                self.wfile_write(data)
        else:
            self.close_connection = 1
            self.retryable = False
            while 1:
                try:
                    data = self.remotesoc.recv(self.bufsize)
                    if not data:
                        raise
                    self.wfile_write(data)
                except Exception:
                    break
        self.wfile_write()
        logging.debug('request finish')
        PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, True if response_status < 400 else False, self.failed_parents, self.ppname)
        if self.close_connection or is_connection_dropped(self.remotesoc):
            self.remotesoc.close()
        else:
            HTTPCONN_POOL.put(self.upstream_name, self.remotesoc, self.ppname if '(pooled)' in self.ppname else self.ppname + '(pooled)')
        self.remotesoc = None

    def on_GET_Error(self, e):
        logging.warning('{} {} via {} failed! {}'.format(self.command, self.shortpath, self.ppname, repr(e)))
        return self._do_GET(True)

    do_POST = do_DELETE = do_TRACE = do_HEAD = do_PUT = do_GET

    def wfile_write(self, data=None):
        if data is None:
            self.retryable = False
        if self.retryable and data:
            self.wbuffer.append(data)
            self.wbuffer_size += len(data)
            if self.wbuffer_size > 102400:
                self.retryable = False
        else:
            if self.wbuffer:
                self.wfile.write(b''.join(self.wbuffer))
                self.wbuffer = deque()
            if data:
                self.wfile.write(data)

    def _http_connect_via_proxy(self, netloc):
        if not self.failed_parents:
            res = HTTPCONN_POOL.get(self.upstream_name)
            if res:
                self._proxylist.insert(0, self.ppname)
                sock, self.ppname = res
                logging.info('{} {} via {} client: {}'.format(self.command, self.shortpath, self.ppname, self.ssclient))
                return sock
        return self._connect_via_proxy(netloc)

    def _connect_via_proxy(self, netloc):
        timeout = None if self._proxylist else 20
        logging.info('{} {} via {} client: {}'.format(self.command, self.shortpath or self.path, self.ppname, self.ssclient))
        if not self.pproxy:
            return create_connection(netloc, timeout or 5)
        elif self.pproxy.startswith('http://'):
            return create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 80), timeout or 10)
        elif self.pproxy.startswith('https://'):
            s = create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 443), timeout or 10)
            s = ssl.wrap_socket(s)
            s.do_handshake()
            return s
        elif self.pproxy.startswith('ss://'):
            s = sssocket(self.pproxy, timeout, conf.parentdict.get('direct')[0])
            s.connect(netloc)
            return s
        elif self.pproxy.startswith('socks5://'):
            s = create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 1080), timeout or 10)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(b"\x05\x02\x00\x02" if self.pproxyparse.username else b"\x05\x01\x00")
            data = s.recv(2)
            if data == b'\x05\x02':  # basic auth
                s.sendall(b''.join([b"\x01",
                                    chr(len(self.pproxyparse.username)).encode(),
                                    self.pproxyparse.username.encode(),
                                    chr(len(self.pproxyparse.password)).encode(),
                                    self.pproxyparse.password.encode()]))
                data = s.recv(2)
            assert data[1] == b'\x00'  # no auth needed or auth passed
            s.sendall(b''.join([b"\x05\x01\x00\x03",
                                chr(len(netloc[0])).encode(),
                                netloc[0].encode(),
                                struct.pack(b">H", netloc[1])]))
            data = s.recv(4)
            assert data[1] == b'\x00'
            if data[3] == b'\x01':  # read ipv4 addr
                s.recv(4)
            elif data[3] == b'\x03':  # read host addr
                s.recv(ord(s.recv(1)))
            elif data[3] == b'\x04':  # read ipv6 addr
                s.recv(16)
            s.recv(2)  # read port
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            return s

    def _read_write(self, soc, max_idling=20):
        iw = [self.connection, soc]
        count = 0
        while True:
            try:
                (ins, _, _) = select.select(iw, [], [], 1)
                for i in ins:
                    data = i.recv(self.bufsize)
                    if data:
                        method = self.wfile.write if i is soc else soc.sendall
                        method(data)
                        count = 0
                    elif count < max_idling:
                        count = max_idling  # make sure all data are read before we close the sockets
                if count > max_idling:
                    break
                count += 1
            except socket.error as e:
                logging.debug('socket error: %s' % e)
                break


class sssocket(object):
    bufsize = 8192

    def __init__(self, ssServer, timeout=10, parentproxy=''):
        self.ssServer = ssServer
        self.timeout = timeout
        self.parentproxy = parentproxy
        self.pproxyparse = urlparse.urlparse(parentproxy)
        self._sock = None
        self.crypto = None
        self.__remote = None
        self.connected = False
        self.__rbuffer = StringIO()

    def connect(self, address):
        self.__address = address
        p = urlparse.urlparse(self.ssServer)
        sshost, ssport, ssmethod, sspassword = (p.hostname, p.port, p.username, p.password)
        self.crypto = encrypt.Encryptor(sspassword, ssmethod)
        if not self.parentproxy:
            self._sock = create_connection((sshost, ssport), self.timeout)
        elif self.parentproxy.startswith('http://'):
            self._sock = create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 80), self.timeout)
            s = 'CONNECT %s:%s HTTP/1.1\r\nHost: %s\r\n' % (sshost, ssport, sshost)
            if self.pproxyparse.username:
                a = '%s:%s' % (self.pproxyparse.username, self.pproxyparse.password)
                s += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(a.encode())
            s += '\r\n'
            self._sock.sendall(s.encode())
            remoterfile = self._sock.makefile('rb', 0)
            data = remoterfile.readline()
            if b'200' not in data:
                raise IOError(0, 'bad response: %s' % data)
            while not data in (b'\r\n', b'\n', b''):
                data = remoterfile.readline()
        else:
            logging.error('sssocket does not support parent proxy server: %s for now' % self.parentproxy)
            return 1
        self.setsockopt = self._sock.setsockopt
        self.fileno = self._sock.fileno

    def recv(self, size):
        if not self.connected:
            self.sendall(b'')
        buf = self.__rbuffer
        buf.seek(0, 2)  # seek end
        buf_len = buf.tell()
        self.__rbuffer = StringIO()  # reset _rbuf.  we consume it via buf.
        if buf_len < size:
            # Not enough data in buffer?  Try to read.
            data = self.crypto.decrypt(self._sock.recv(max(size - buf_len, self.bufsize)))
            if len(data) == size and not buf_len:
                # Shortcut.  Avoid buffer data copies
                return data
            buf.write(data)
            del data  # explicit free
        buf.seek(0)
        rv = buf.read(size)
        self.__rbuffer.write(buf.read())
        return rv

    def sendall(self, data):
        if self.connected:
            self._sock.sendall(self.crypto.encrypt(data))
        else:
            host, port = self.__address
            self._sock.sendall(self.crypto.encrypt(b''.join([b'\x03',
                                                   chr(len(host)).encode(),
                                                   host.encode(),
                                                   struct.pack(b">H", port),
                                                   data])))
            self.connected = True

    def readline(self, size=-1):
        buf = self.__rbuffer
        buf.seek(0, 2)  # seek end
        if buf.tell() > 0:
            # check if we already have it in our buffer
            buf.seek(0)
            bline = buf.readline(size)
            if bline.endswith('\n') or len(bline) == size:
                self.__rbuffer = StringIO()
                self.__rbuffer.write(buf.read())
                return bline
            del bline
        if size < 0:
            # Read until \n or EOF, whichever comes first
            buf.seek(0, 2)  # seek end
            self.__rbuffer = StringIO()  # reset _rbuf.  we consume it via buf.
            while True:
                try:
                    data = self.recv(self.bufsize)
                except socket.error as e:
                    if e.args[0] == errno.EINTR:
                        continue
                    raise
                if not data:
                    break
                nl = data.find(b'\n')
                if nl >= 0:
                    nl += 1
                    buf.write(data[:nl])
                    self.__rbuffer.write(data[nl:])
                    break
                buf.write(data)
            del data
            return buf.getvalue()
        else:
            # Read until size bytes or \n or EOF seen, whichever comes first
            buf.seek(0, 2)  # seek end
            buf_len = buf.tell()
            if buf_len >= size:
                buf.seek(0)
                rv = buf.read(size)
                self.__rbuffer = StringIO()
                self.__rbuffer.write(buf.read())
                return rv
            self.__rbuffer = StringIO()  # reset _rbuf.  we consume it via buf.
            while True:
                try:
                    data = self.recv(self.bufsize)
                except socket.error as e:
                    if e.args[0] == errno.EINTR:
                        continue
                    raise
                if not data:
                    break
                left = size - buf_len
                # did we just receive a newline?
                nl = data.find(b'\n', 0, left)
                if nl >= 0:
                    nl += 1
                    # save the excess data to _rbuf
                    self.__rbuffer.write(data[nl:])
                    if buf_len:
                        buf.write(data[:nl])
                        break
                    else:
                        # Shortcut.  Avoid data copy through buf when returning
                        # a substring of our first recv().
                        return data[:nl]
                n = len(data)
                if n == size and not buf_len:
                    # Shortcut.  Avoid data copy through buf when
                    # returning exactly all of our first recv().
                    return data
                if n >= left:
                    buf.write(data[:left])
                    self.__rbuffer.write(data[left:])
                    break
                buf.write(data)
                buf_len += n
                #assert buf_len == buf.tell()
            return buf.getvalue()

    def close(self):
        if self._sock:
            self._sock.close()

    def __del__(self):
        self.close()


class ExpiredError(Exception):
    pass


class autoproxy_rule(object):
    def __init__(self, arg, expire=None):
        super(autoproxy_rule, self).__init__()
        self.rule = arg.strip()
        logging.debug('parsing autoproxy rule: %r' % self.rule)
        if len(self.rule) < 3 or self.rule.startswith(('!', '[')) or '#' in self.rule:
            raise TypeError("invalid autoproxy_rule: %s" % self.rule)
        self.expire = expire
        self._ptrn = self._autopxy_rule_parse(self.rule)

    def _autopxy_rule_parse(self, rule):
        def parse(rule):
            if rule.startswith('||'):
                regex = rule.replace('.', r'\.').replace('?', r'\?').replace('/', '').replace('*', '[^/]*').replace('^', r'[^\w%._-]').replace('||', '^(?:https?://)?(?:[^/]+\.)?') + r'(?:[:/]|$)'
                return re.compile(regex)
            elif rule.startswith('/') and rule.endswith('/'):
                return re.compile(rule[1:-1])
            elif rule.startswith('|https://'):
                i = rule.find('/', 9)
                regex = rule[9:] if i == -1 else rule[9:i]
                regex = r'^(?:https://)?%s(?:[:/])' % regex.replace('.', r'\.').replace('*', '[^/]*')
                return re.compile(regex)
            else:
                regex = rule.replace('.', r'\.').replace('?', r'\?').replace('*', '.*').replace('^', r'[^\w%._-]')
                regex = re.sub(r'^\|', r'^', regex)
                regex = re.sub(r'\|$', r'$', regex)
                if not rule.startswith('|'):
                    regex = re.sub(r'^', r'^http://.*', regex)
                return re.compile(regex)

        self.override = rule.startswith('@@')
        return parse(rule[2:]) if self.override else parse(rule)

    def match(self, uri):
        if self.expire and self.expire < time.time():
            raise ExpiredError
        return self._ptrn.search(uri)


class redirector(object):
    """docstring for redirector"""
    def __init__(self):
        self.lst = []

    def get(self, uri, host=None):
        searchword = re.match(r'^http://([\w-]+)/$', uri)
        if searchword:
            q = searchword.group(1)
            if 'xn--' in q:
                q = q.encode().decode('idna')
            logging.debug('Match redirect rule addressbar-search')
            return 'https://www.google.com/search?q=%s&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:zh-CN:official' % urlquote(q.encode('utf-8'))
        for rule, result in self.lst:
            if rule.match(uri):
                logging.debug('Match redirect rule {}, {}'.format(rule.rule, result))
                if rule.override:
                    return None
                if result == 'forcehttps':
                    return uri.replace('http://', 'https://', 1)
                if result.startswith('/') and result.endswith('/'):
                    return rule._ptrn.sub(result[1:-1], uri)
                return result


class parent_proxy(object):
    """docstring for parent_proxy"""
    def config(self):
        self.override = []
        self.gfwlist_force = []
        self.temp_rules = set()
        REDIRECTOR.lst = []

        for line in open('./rproxy/local.txt'):
            self.add_rule(line)

    def add_rule(self, line):
        rule = line.strip().split()
        if len(rule) == 2:  # |http://www.google.com/url forcehttps
            try:
                rule, result = rule
                REDIRECTOR.lst.append((autoproxy_rule(rule), result))
            except TypeError as e:
                logging.debug('create autoproxy rule failed: %s' % e)
        elif len(rule) == 1:
            try:
                o = autoproxy_rule(rule[0])
                if o.override:
                    self.override.append(o)
                self.gfwlist_force.append(o)
            except TypeError as e:
                logging.debug('create autoproxy rule failed: %s' % e)
        elif rule and '!' not in line:
            logging.warning('Bad autoproxy rule: %r' % line)

    @lru_cache(256, timeout=120)
    def ifhost_in_local(self, host, port):
        try:
            return ip_address(getaddrinfo(host, port)[0][4][0]).is_private
        except socket.error as e:
            logging.warning('resolve %s failed! %s' % (host, repr(e)))

    def if_gfwlist_force(self, uri, level):
        if level == 3:
            return True
        for rule in self.gfwlist_force:
            try:
                if rule.match(uri):
                    return True
            except ExpiredError:
                logging.info('%s expired' % rule.rule)
                self.gfwlist_force.remove(rule)
                self.temp_rules.discard(rule.rule)

    def ifgfwed(self, uri, host, port, level=1):
        if level == 0:
            return False
        elif level == 2:
            forceproxy = True
        else:
            forceproxy = False

        gfwlist_force = self.if_gfwlist_force(uri, level)

        if any(rule.match(uri) for rule in self.override):
            return None

        if gfwlist_force or forceproxy:
            return True

    def parentproxy(self, uri, host, command, level=1):
        '''
            decide which parentproxy to use.
            url:  'www.google.com:443'
                  'http://www.inxian.com'
            host: ('www.google.com', 443) (no port number is allowed)
            level: 0 -- direct
                   1 -- proxy if force, direct if ip in region or override, proxy if gfwlist
                   2 -- proxy if force, direct if ip in region or override, proxy if all
                   3 -- proxy if not override
        '''
        host, port = host

        if self.ifhost_in_local(host, port):
            return ['local' if 'local' in conf.parentdict.keys() else 'direct']

        f = self.ifgfwed(uri, host, port, level)

        parentlist = list(conf.parentdict.keys())
        random.shuffle(parentlist)
        parentlist = sorted(parentlist, key=lambda item: conf.parentdict[item][1])

        if 'local' in parentlist:
            parentlist.remove('local')

        if f is True:
            parentlist.remove('direct')
            if not parentlist:
                logging.warning('No parent proxy available, direct connection is used')
                return ['direct']
        if len(parentlist) > conf.maxretry + 1:
            parentlist = parentlist[:conf.maxretry + 1]
        return parentlist

    def notify(self, method, url, requesthost, success, failed_parents, current_parent):
        logging.debug('notify: %s %s %s, failed_parents: %r, final: %s' % (method, url, 'Success' if success else 'Failed', failed_parents, current_parent or 'None'))
        failed_parents = [k for k in failed_parents if 'pooled' not in k]
        if 'direct' in failed_parents and success:
            if method == 'CONNECT':
                rule = '|https://%s' % requesthost[0]
            else:
                rule = '|http://%s' % requesthost[0] if requesthost[1] == 80 else '%s:%d' % requesthost
            if rule not in self.temp_rules:
                logging.info('add autoproxy rule: %s' % rule)
                self.gfwlist_force.append(autoproxy_rule(rule, expire=time.time() + 60 * 10))
                self.temp_rules.add(rule)


def updater():
    while 1:
        time.sleep(30)
        HTTPCONN_POOL.purge()


class SConfigParser(configparser.ConfigParser):
    """docstring for SSafeConfigParser"""
    optionxform = str

    def dget(self, section, option, default=''):
        try:
            value = self.get(section, option)
            if not value:
                value = default
        except Exception:
            value = default
        return value

    def dgetfloat(self, section, option, default=0):
        try:
            return self.getfloat(section, option)
        except Exception:
            return float(default)

    def dgetint(self, section, option, default=0):
        try:
            return self.getint(section, option)
        except Exception:
            return int(default)

    def dgetbool(self, section, option, default=False):
        try:
            return self.getboolean(section, option)
        except Exception:
            return bool(default)

    def items(self, section):
        try:
            return configparser.ConfigParser.items(self, section)
        except Exception:
            return []

    def set(self, section, option, value):
        if not self.has_section(section):
            self.add_section(section)
        configparser.ConfigParser.set(self, section, option, value)


class Config(object):
    def __init__(self):
        self.version = SConfigParser()
        self.userconf = SConfigParser()
        self.reload()
        self.UPDATE_INTV = 6
        self.parentdict = {'direct': ('', 0), }
        self.FAKEHTTPS = set()
        self.WITHGAE = set()
        self.HOST = tuple()
        self.HOST_POSTFIX = tuple()
        self.CONN_POSTFIX = tuple()
        listen = self.userconf.dget('rproxy', 'listen', '8118')
        if listen.isdigit():
            self.listen = ('127.0.0.1', int(listen))
        else:
            self.listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))

        self.region = set(x.upper() for x in self.userconf.dget('rproxy', 'region', 'cn').split('|') if x.strip())

        self.xheaders = self.userconf.dgetbool('rproxy', 'xheaders', True)

        if self.userconf.dget('rproxy', 'parentproxy', ''):
            self.addparentproxy('direct', '%s 0' % self.userconf.dget('rproxy', 'parentproxy', ''))
            self.addparentproxy('local', 'direct 100')

        self.maxretry = self.userconf.dgetint('rproxy', 'maxretry', 4)

    def reload(self):
        self.userconf.read('userconf.ini')

    def addparentproxy(self, name, proxy):
        '''
        {
            'direct': ('', 0),
            'goagent': ('http://127.0.0.1:8087', 20)
        }
        '''
        proxy, _, priority = proxy.partition(' ')
        if proxy == 'direct':
            proxy = ''
        priority = int(priority) if priority else (0 if name == 'direct' else 99)
        if proxy and not '//' in proxy:
            proxy = 'http://%s' % proxy
        logging.info('adding parent proxy: %s: %s' % (name, proxy))
        self.parentdict[name] = (proxy, priority)

REDIRECTOR = redirector()
PARENT_PROXY = parent_proxy()
conf = Config()
PARENT_PROXY.config()


def main():
    if os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(u'rproxy v%s' % __version__)
    for k, v in conf.userconf.items('parents'):
        conf.addparentproxy(k, v)
    updatedaemon = Thread(target=updater)
    updatedaemon.daemon = True
    updatedaemon.start()
    server = ThreadingHTTPServer(conf.listen, ProxyHandler)
    server.serve_forever()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
