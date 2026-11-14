"""Processo de exemplo do harness: envia um byte a URL dada e anuncia o eco recebido."""
import json
import sys
import urllib.request

req = urllib.request.Request(sys.argv[1], data=b"\x2a", method="POST")
with urllib.request.urlopen(req, timeout=10) as resp:
    echoed = resp.read()
print("READY " + json.dumps({"echo": echoed.hex()}), flush=True)
