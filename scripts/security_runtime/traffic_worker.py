#!/usr/bin/env python3
"""C3/C4 single-hop HTTP worker. Never navigates, retries or runs target code."""

import base64
import http.client
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_runtime.common import canonical, fields, integer, parse, require, sha256
from security_runtime.web_scope import address, credential, url
from security_runtime.parent_guard import bind_worker


def collect(value):
    fields(value, {'url','method','addresses','network','timeout','limit','credential','ca','body','parent_pid'})
    bind_worker(value['parent_pid'])
    scheme, host, port, path = url(value['url'])
    integer(value['timeout'], 1, 15)
    integer(value['limit'], 1, 262144)
    require(value['method'] in {'GET','HEAD','POST','PUT','PATCH','DELETE'}, 'unsupported method')
    body = base64.b64decode(value['body'], validate=True)
    require(len(body) <= 65536 and (value['method'] not in {'GET','HEAD'} or not body), 'unsupported request body')
    pins = {str(address(item, value['network'])) for item in value['addresses']}
    require(0 < len(pins) <= 8 and (scheme == 'https' or value['network'] == 'loopback'), 'unsupported destination')
    if value['credential'] is not None: credential(value['credential'])
    try: resolved = {str(ipaddress.ip_address(host))}
    except ValueError: resolved = {str(ipaddress.ip_address(row[4][0])) for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    require(resolved and resolved <= pins, 'DNS differs from authorized pins')
    selected = sorted(resolved)[0]
    sock = socket.socket(socket.AF_INET6 if ':' in selected else socket.AF_INET, socket.SOCK_STREAM)
    connection = None
    try:
        sock.settimeout(value['timeout'])
        sock.connect((selected, port))
        if scheme == 'https':
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if value['ca'] is not None:
                require(isinstance(value['ca'], str) and len(value['ca']) <= 4096, 'CA exceeds limit')
                context.load_verify_locations(cadata=value['ca'])
            sock = context.wrap_socket(sock, server_hostname=host)
        http.client._MAXLINE, http.client._MAXHEADERS = 8192, 32
        connection = http.client.HTTPConnection(host, port, timeout=value['timeout'])
        connection.sock = sock
        headers = {'User-Agent':'Cybersecurity-Skills-C3-C4','Accept-Encoding':'identity','Connection':'close'}
        if body: headers['Content-Type'] = 'application/json'
        if value['credential'] is not None: headers[value['credential']['header']] = value['credential']['value']
        connection.request(value['method'], path, body=body or None, headers=headers)
        response = connection.getresponse()
        pairs = response.getheaders()
        require(sum(len(k)+len(v) for k,v in pairs) <= 32768, 'response headers exceed limit')
        lengths = response.headers.get_all('Content-Length', [])
        require(len(lengths) <= 1 and (not lengths or lengths[0].isdecimal() and
                (value['method'] == 'HEAD' or int(lengths[0]) <= value['limit'])), 'invalid response length')
        require(not (lengths and response.getheader('Transfer-Encoding')) and response.getheader('Content-Encoding','identity').lower() == 'identity', 'unsupported response framing')
        raw = response.read(value['limit'] + 1)
        require(len(raw) <= value['limit'] and (not lengths or value['method']=='HEAD' or len(raw)==int(lengths[0])), 'truncated or oversized response')
        require(len(response.headers.get_all('Location', [])) <= 1, 'ambiguous redirect')
        return {'schema_version':1,'status':response.status,'headers':pairs,'body':base64.b64encode(raw).decode(),
                'body_bytes':len(raw),'body_sha256':sha256(raw),'address':selected}
    finally:
        if connection is not None: connection.close()
        sock.close()


if __name__ == '__main__':
    timer = threading.Timer(15, lambda: os._exit(124))
    timer.daemon = True
    timer.start()
    try:
        sys.stdout.buffer.write(canonical(collect(parse(sys.stdin.buffer.read(110001), 110000))))
    except Exception:
        raise SystemExit(1)
    finally:
        timer.cancel()
