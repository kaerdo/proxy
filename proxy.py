#!/usr/bin/env python
#coding:utf-8

import logging
import socket
import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
import tornado.httpclient
from tornado import gen

logger = logging.getLogger()


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    @gen.coroutine
    def get(self):
        logger.debug('Handle %s request to %s', self.request.method, self.request.uri)

        def handle_response(response):
            if (response.error and not
                    isinstance(response.error, tornado.httpclient.HTTPError)):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
            else:
                self.set_status(response.code)
                for header in ('Date', 'Cache-Control', 'Server', 'Content-Type', 'Location'):
                    v = response.headers.get(header)
                    if v:
                        self.set_header(header, v)
                v = response.headers.get_list('Set-Cookie')
                if v:
                    for i in v:
                        self.add_header('Set-Cookie', i)
                self.add_header('VIA', 'Toproxy')
                if response.body:
                    self.write(response.body)
            self.finish()

        if base_auth_user:
            auth_header = self.request.headers.get('Authorization', '')
            if not base_auth_valid(auth_header):
                self.set_status(403)
                self.write('Auth Faild')
                self.finish()
                return

        client_ip = self.request.remote_ip
        if not match_white_iplist(client_ip):
            logger.debug('deny %s', client_ip)
            self.set_status(403)
            self.write('')
            self.finish()
            return

        body = self.request.body
        if not body:
            body = None
        try:
            response = yield fetch_request(self.request.uri)
            handle_response(response)
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        logger.debug('Start CONNECT to %s', self.request.uri)
        host, port = self.request.uri.split(':')
        client = self.request.connection.stream

        def read_from_client(data):
            upstream.write(data)

        def read_from_upstream(data):
            client.write(data)

        def client_close(data=None):
            if upstream.closed():
                return
            if data:
                upstream.write(data)
            upstream.close()

        def upstream_close(data=None):
            if client.closed():
                return
            if data:
                client.write(data)
            client.close()

        def start_tunnel():
            logger.debug('CONNECT tunnel established to %s', self.request.uri)
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        upstream = tornado.iostream.IOStream(s)
        upstream.connect((host, int(port)), start_tunnel)


def base_auth_valid(auth_header):
    auth_mode, auth_base64 = auth_header.split(' ', 1)
    assert auth_mode == 'Basic'
    auth_username, auth_password = auth_base64.split(':', 1)
    if auth_username == base_auth_user and auth_password == base_auth_passwd:
        return True
    else:
        return False

def match_white_iplist(clientip):
    if clientip in white_iplist:
        return True
    if not white_iplist:
        return True
    return False

@gen.coroutine
def fetch_request(url, **kwargs):
    req = tornado.httpclient.HTTPRequest(url, **kwargs)
    client = tornado.httpclient.AsyncHTTPClient()
    rep = yield client.fetch(req)
    raise gen.Return(rep)

def run_proxy(port, pnum=1, start_ioloop=True):
    import tornado.process
    app = tornado.web.Application([
        (r'.*', ProxyHandler),
    ])

    if pnum > 200 or pnum < 0:
        raise("process num is too big or small")
    if pnum == 1:
        app.listen(port)
        ioloop = tornado.ioloop.IOLoop.instance()
        if start_ioloop:
            ioloop.start()
    else:
        sockets = tornado.netutil.bind_sockets(port)
        tornado.process.fork_processes(pnum)
        server = tornado.httpserver.httpserver(app)
        server.add_sockets(sockets)
        tornado.ioloop.ioloop.instance().start()


if __name__ == '__main__':
    import argparse
    white_iplist = []
    parser = argparse.ArgumentParser(description='''python -m toproxy/proxy  -p 9898 -w 127.0.0.1,8.8.8.8 -u test:test''')

    parser.add_argument('-p', '--port', help='tonado proxy listen port', action='store', default=9898)
    parser.add_argument('-w', '--white', help='white ip list ---> 127.0.0.1,215.8.1.3', action='store', default=[])
    parser.add_argument('-u', '--user', help='Base Auth , test:test', action='store', default=None)
    parser.add_argument('-f', '--fork', help='fork process to support', action='store', default=1)
    args = parser.parse_args()

    if not args.port:
        parser.print_help()

    port = int(args.port)
    white_iplist = args.white

    if args.user:
        base_auth_user, base_auth_passwd = args.user.split(':')
    else:
        base_auth_user, base_auth_passwd = None, None

    print ("Starting HTTP proxy on port %d" % port)
    pnum = int(args.fork)
    run_proxy(port, pnum)
