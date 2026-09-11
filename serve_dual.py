import http.server
import socketserver
import ssl
import threading
import os
import sys

DIRECTORY = os.path.abspath(r"c:\work\crimenet\backend\src\main\resources\static")
HTTP_PORT = 8080
HTTPS_PORT = 8443
CERT_FILE = os.path.abspath(r"c:\work\crimenet\server.crt")
KEY_FILE = os.path.abspath(r"c:\work\crimenet\server.key")

class CrimeNetHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def copyfile(self, source, outputfile):
        try:
            super().copyfile(source, outputfile)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Cache-Control', 'no-cache, must-revalidate')
        super().end_headers()

    def guess_type(self, path):
        if path.endswith('.json') or path.endswith('manifest.json'):
            return 'application/manifest+json'
        if path.endswith('.js'):
            return 'application/javascript'
        if path.endswith('.css'):
            return 'text/css'
        if path.endswith('.pdf'):
            return 'application/pdf'
        return super().guess_type(path)

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class SecureTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    def __init__(self, server_address, RequestHandlerClass, ssl_context, bind_and_activate=True):
        self.ssl_context = ssl_context
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            wrapped_sock = self.ssl_context.wrap_socket(sock, server_side=True)
            return wrapped_sock, addr
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise

def run_http():
    with ReusableTCPServer(("", HTTP_PORT), CrimeNetHandler) as httpd:
        print(f"[*] Plain HTTP Server active on http://0.0.0.0:{HTTP_PORT} (http://10.50.1.249:{HTTP_PORT} / http://172.20.10.2:{HTTP_PORT})", flush=True)
        httpd.serve_forever()

def run_https():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    with SecureTCPServer(("", HTTPS_PORT), CrimeNetHandler, context) as httpsd:
        print(f"[*] Secure HTTPS Server active on https://0.0.0.0:{HTTPS_PORT} (https://10.50.1.249:{HTTPS_PORT} / https://172.20.10.2:{HTTPS_PORT})", flush=True)
        httpsd.serve_forever()

if __name__ == '__main__':
    t1 = threading.Thread(target=run_http, daemon=True)
    t2 = threading.Thread(target=run_https, daemon=True)
    t1.start()
    t2.start()
    print("[*] CrimeNet Dual HTTP/HTTPS Server initialized with Multi-SAN Certificate.", flush=True)
    t1.join()
    t2.join()
