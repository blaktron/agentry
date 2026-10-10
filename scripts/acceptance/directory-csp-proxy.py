"""Private browser-fixture proxy; never used by the deployed directory."""
import http.client
import http.server
import os
import ssl
from urllib.parse import urlsplit

upstream = urlsplit(os.environ['AK'])
policy = os.environ['DIRECTORY_CSP']
probe = b'''<script>window.agentryInjectedScript = true;</script>
<img alt="" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" onload="window.agentryInjectedHandler = true">
<button id="agentry-injected-click" onclick="window.agentryInjectedClick = true">Injection fixture</button>'''


class Proxy(http.server.BaseHTTPRequestHandler):
    def exchange(self):
        conn = http.client.HTTPConnection(upstream.hostname, upstream.port, timeout=60)
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ('connection', 'content-length', 'accept-encoding')}
        headers['X-Forwarded-Proto'] = 'https'
        conn.request(self.command, self.path, body, headers)
        res = conn.getresponse()
        data = res.read()
        html = self.path.startswith('/if/flow/') and res.getheader('Content-Type', '').startswith('text/html')
        if html and urlsplit(self.path).path == '/if/flow/default-authentication-flow/':
            data = data.replace(b'</body>', probe + b'</body>')
        self.send_response(res.status)
        for name, value in res.getheaders():
            if name.lower() not in ('connection', 'content-length', 'transfer-encoding'):
                self.send_header(name, value)
        if html and res.getheader('Content-Security-Policy') is None:
            self.send_header('Content-Security-Policy', policy)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()

    do_GET = do_POST = exchange

    def log_message(self, *_):
        pass


server = http.server.ThreadingHTTPServer(('0.0.0.0', 8443), Proxy)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/fixture.crt', '/fixture.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
