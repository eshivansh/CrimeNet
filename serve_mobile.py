import http.server
import socketserver
import urllib.request
import os
import sys

PORT = 8081
STATIC_DIR = os.path.abspath(r"c:\work\crimenet\backend\src\main\resources\static")
BACKEND_API_BASE = "http://127.0.0.1:8080"

class MobileAppHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        # Reverse proxy real Spring Boot API calls
        if self.path.startswith('/api/'):
            self._proxy_to_backend('GET')
            return

        # Serve mobile app as default root
        clean_path = self.path.split('?')[0].rstrip('/')
        if clean_path in ['', '/index.html']:
            mobile_file = os.path.join(STATIC_DIR, 'mobile', 'index.html')
            if os.path.exists(mobile_file):
                with open(mobile_file, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        super().do_GET()

    def do_POST(self):
        if self.path.startswith('/api/'):
            self._proxy_to_backend('POST')
            return
        self.send_error(404, "Endpoint not found")

    def _proxy_to_backend(self, method):
        target_url = f"{BACKEND_API_BASE}{self.path}"
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            headers = {k: v for k, v in self.headers.items() if k.lower() not in ['host', 'content-length']}
            req = urllib.request.Request(target_url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(req) as resp:
                resp_data = resp.read()
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() not in ['content-length', 'transfer-encoding', 'connection']:
                        self.send_header(k, v)
                self.send_header('Content-Length', str(len(resp_data)))
                self.end_headers()
                self.wfile.write(resp_data)
        except urllib.error.HTTPError as e:
            err_data = e.read()
            self.send_response(e.code)
            self.send_header('Content-Type', e.headers.get('Content-Type', 'application/json'))
            self.send_header('Content-Length', str(len(err_data)))
            self.end_headers()
            self.wfile.write(err_data)
        except Exception as e:
            err_resp = f'{{"error": "{str(e)}"}}'.encode('utf-8')
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(err_resp)))
            self.end_headers()
            self.wfile.write(err_resp)

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    with ReusableTCPServer(("", PORT), MobileAppHandler) as httpd:
        print(f"[*] CrimeNet Dedicated Mobile App Server active on port {PORT}", flush=True)
        print(f"[*] Access on iPhone (Tailscale): http://100.79.221.75:{PORT}/", flush=True)
        print(f"[*] Access locally: http://localhost:{PORT}/", flush=True)
        httpd.serve_forever()
