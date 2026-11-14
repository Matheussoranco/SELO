"""Processo de exemplo do harness: devolve o corpo recebido. Anuncia READY {"url": ...}."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
print("READY " + json.dumps({"url": f"http://127.0.0.1:{srv.server_address[1]}"}), flush=True)
srv.serve_forever()
