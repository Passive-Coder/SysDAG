import socket
from pathlib import Path

try:
    payload = Path("/guest/www/index.html").read_bytes()
except FileNotFoundError:
    payload = b""

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(0.2)
    try:
        sock.connect(("127.0.0.1", 9999))
        sock.sendall(payload)
    except OSError:
        pass
