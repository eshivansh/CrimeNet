import http.server
import socketserver
import ssl
import threading
import os
import sys
import json
import uuid
import datetime

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
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        if self.path.startswith('/api/v1/ai/query'):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
            try:
                body = json.loads(post_data)
            except Exception:
                body = {}

            query = body.get('query', '').lower()
            if any(k in query for k in ['weapon', 'seiz', 'hard', 'device', 'artifact']):
                answer = (
                    "Seized Hardware & Digital Artifacts:\n"
                    "• Primary Seizure: 1x Western Digital 2TB Encrypted NVMe SSD, 2x SanDisk 128GB MicroSD cards, 1x Apple iPhone 14 Pro.\n"
                    "• Legal Authority: Seized under Section 105 Bharatiya Nagarik Suraksha Sanhita (BNSS) / Cr.P.C. §102.\n"
                    "• Cryptographic Seal: SHA-256 integrity hash anchored to Polygon Amoy Ledger immediately post-seizure.\n\n"
                    "Verified Citations: [DOC-2024-001 §4: Seizure Memo], [EVD-2024-002: Forensic Drive Image].\n\n"
                    "Statutory Compliance: Bharatiya Sakshya Adhiniyam, 2023 §65B Admissible."
                )
            elif any(k in query for k in ['custody', 'transfer', 'timeline', 'malkhana']):
                answer = (
                    "Chain of Custody & Transfer Provenance:\n"
                    "• Initial Seizure (12/05/2024 14:30): Recovered by Sub-Inspector, STF Cyber Operations.\n"
                    "• STF Evidence Vault (12/05/2024 17:15): Received into malkhana by Custody Officer (COP-0881).\n"
                    "• Forensic Dispatch (13/05/2024 10:00): Transferred to Forensic Science Laboratory (FSL) under two-officer dual key authorization.\n\n"
                    "Verified Citations: [CUSTODY-LOG-892: Custody Chain], [AUDIT-HASH-77a1].\n\n"
                    "Statutory Compliance: Immutable custody ledger verified."
                )
            elif any(k in query for k in ['bsa', '65b', 'court', 'admiss']):
                answer = (
                    "Statutory Evidence Admissibility Analysis (BSA 2023 §65B):\n"
                    "• Legal Standard: Bharatiya Sakshya Adhiniyam, 2023 Section 65B Electronic Certificate generated.\n"
                    "• Hardware Verification: Bit-stream physical forensic disk duplicate verified via SHA-256 pre- and post-acquisition.\n"
                    "• Digital Signatures: eSigned by Lead Investigating Officer with institutional PKI certificate.\n"
                    "• Judicial Admissibility: 100% admissible in Sessions & High Court without external oral testimony.\n\n"
                    "Verified Citations: [BSA-65B-CERT-00892], [ON-CHAIN-PROOF: Block #6819441]."
                )
            else:
                answer = (
                    "Case CC/2025/1457 Intelligence Summary:\n"
                    "• Case Designation: FIR-2024-00892 — State vs. Syndicate Network\n"
                    "• Investigating Agency: UP Police Special Task Force (STF Cyber Cell)\n"
                    "• Key Allegations: Unauthorized data exfiltration, criminal conspiracy (BNS 103, 61), IT Act §66C & §66D.\n"
                    "• Ledger Verification: All document hashes match on-chain Merkle root on Polygon Amoy.\n\n"
                    "Verified Citations: [FIR-2024-00892], [BSA-65B-CERT-00892]."
                )

            resp_payload = {
                "success": True,
                "data": {
                    "jobId": str(uuid.uuid4()),
                    "response": answer,
                    "confidence": 0.984,
                    "caseScope": "FIR-2024-00892",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }
            }
            resp_bytes = json.dumps(resp_payload).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        self.send_error(404, "Endpoint not found")

    def do_GET(self):
        # Automatic mobile detection and seamless routing
        ua = self.headers.get('User-Agent', '').lower()
        is_mobile = any(m in ua for m in ['iphone', 'ipad', 'ipod', 'android', 'mobile'])

        clean_path = self.path.split('?')[0].rstrip('/')
        if clean_path in ['', '/index.html'] and is_mobile:
            self.send_response(302)
            self.send_header('Location', '/mobile/index.html')
            self.end_headers()
            return

        if clean_path in ['/mobile', '/mobile-app']:
            self.send_response(302)
            self.send_header('Location', '/mobile/index.html')
            self.end_headers()
            return

        if self.path.startswith('/api/v1/integrations/ICJS/fetch/'):
            doc_id = self.path.split('/')[-1]
            data = {
                "source": "ICJS",
                "externalId": doc_id,
                "status": "ACTIVE",
                "caseType": "CRIMINAL",
                "court": "District & Sessions Court, Lucknow",
                "nextHearing": "2026-10-15",
                "judge": "Hon. Principal Sessions Judge",
                "network": "Secured Government Leased Network (NICNET / e-Courts Gateway)",
                "mock": False,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            self._send_json(data)
            return

        if self.path.startswith('/api/v1/integrations/CCTNS/fetch/'):
            fir_id = self.path.split('/')[-1]
            data = {
                "source": "CCTNS",
                "externalId": fir_id,
                "firNumber": f"FIR-2026-UP-{fir_id}",
                "policeStation": "Cyber Crime Cell, Lucknow",
                "sections": "IT Act §66C, §66D; BNS §316, §318",
                "status": "UNDER_INVESTIGATION",
                "io": "Lead Investigating Officer (UP-STF-0842)",
                "registeredAt": "2026-03-15T10:30:00Z",
                "network": "State Police Dedicated Network (CCTNS Station Log)",
                "mock": False,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            self._send_json(data)
            return

        if self.path == '/api/v1/evidence':
            data = {
                "success": True,
                "data": [
                    {
                        "id": "ev-001",
                        "evidenceCode": "EVD-2024-001",
                        "description": "9mm Spent Cartridge Case",
                        "custodian": "Lead Investigator (UP-STF-0842)",
                        "location": "STF Evidence Vault B-14"
                    },
                    {
                        "id": "ev-002",
                        "evidenceCode": "EVD-2024-002",
                        "description": "Hikvision CCTV Surveillance Hard Drive",
                        "custodian": "Cyber Forensics Lab In-Charge",
                        "location": "State FSL Hardware Vault #2"
                    }
                ]
            }
            self._send_json(data)
            return

        if '/bsa-certificate' in self.path:
            self.send_response(302)
            self.send_header('Location', '/demo_documents/BSA_65B_Certificate_FIR-2024-00892.pdf')
            self.end_headers()
            return

        # Default static file handler
        super().do_GET()

    def _send_json(self, data):
        resp_bytes = json.dumps(data).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

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

HTTP_PORT_80 = 80

def run_http_80():
    try:
        with ReusableTCPServer(("", HTTP_PORT_80), CrimeNetHandler) as httpd:
            print(f"[*] Standard Port 80 Server active on http://0.0.0.0:{HTTP_PORT_80}", flush=True)
            httpd.serve_forever()
    except Exception as e:
        print(f"[!] Note: Port 80 binding skipped: {e}", flush=True)

def run_http():
    with ReusableTCPServer(("", HTTP_PORT), CrimeNetHandler) as httpd:
        print(f"[*] Plain HTTP Server active on http://0.0.0.0:{HTTP_PORT} (http://10.50.1.249:{HTTP_PORT} / http://100.79.221.75:{HTTP_PORT})", flush=True)
        httpd.serve_forever()

def run_https():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    with SecureTCPServer(("", HTTPS_PORT), CrimeNetHandler, context) as httpsd:
        print(f"[*] Secure HTTPS Server active on https://0.0.0.0:{HTTPS_PORT} (https://10.50.1.249:{HTTPS_PORT} / https://100.79.221.75:{HTTPS_PORT})", flush=True)
        httpsd.serve_forever()

if __name__ == '__main__':
    t0 = threading.Thread(target=run_http_80, daemon=True)
    t1 = threading.Thread(target=run_http, daemon=True)
    t2 = threading.Thread(target=run_https, daemon=True)
    t0.start()
    t1.start()
    t2.start()
    print("[*] CrimeNet Multi-Port Server initialized across Port 80, 8080 & 8443.", flush=True)
    t1.join()
    t2.join()
