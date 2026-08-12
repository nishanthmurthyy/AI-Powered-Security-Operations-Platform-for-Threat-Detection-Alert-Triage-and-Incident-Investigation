import socket
import ssl
from pprint import pprint

host = "generativelanguage.googleapis.com"

context = ssl._create_unverified_context()

with socket.create_connection((host, 443), timeout=10) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        cert = ssock.getpeercert()

print("TLS Version:", ssock.version())
pprint(cert)